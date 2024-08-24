import "dotenv/config";
import chalk from "chalk";
import express from "express";
import morgan from "morgan";
import session from "express-session";
import MongoStore from "connect-mongo";
import cors from "cors";
import userdb from "./model/userSchema.js";
import connectionToDB from "./db/connection.js";
import redisConnect from "./db/redis.config.js";
import { postChatGPTMessage } from "./generateComment.js";
import OpenAI from "openai";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import querystring from "querystring";
import axios from "axios";
import cluster from "cluster";
import crypto from "crypto";
import os from "os";
let redisConnectionClient; 

await connectionToDB();
(async()=> {
  redisConnectionClient = await redisConnect(); 
})(); 



const app = express();
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "https://socialscribe-aipoool.onrender.com",
      "chrome-extension://bhnpbgfnodkiohanbolcdkibeibncobf",
      "https://www.linkedin.com",
      "https://x.com",
    ],
    methods: ["GET", "PUT", "POST", "DELETE", "OPTIONS"],
    credentials: true,
  })
);

app.use(cookieParser());


// Middleware
app.use(express.json());


app.set("trust proxy", 1);
app.use(
  session({
    secret: process.env.SECRET_SESSION,
    resave: true, //we dont want to save a session if nothing is modified
    saveUninitialized: true, //dont create a session until something is stored
    store: new MongoStore({
      mongoUrl: process.env.DATABASE,
      collection: 'sessions'
    }),
    cookie: {
      maxAge: 3 * 24 * 60 * 60 * 1000, // 3 days
      secure: "auto",
      sameSite: "none", //Enable when deployment OR when not using localhost, We're not on the same site, we're using different site so the cookie need to effectively transfer from Backend to Frontend
    },
  })
);


if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minutes
  max: 200,
  message:
    "Too many requests from this IP, please try again after some time--..",
});



const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  console.log("The token received at the middleware: ", token);
  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};



app.use(limiter);

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Methods", "PUT, POST, GET, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With"
  );
  next();
});

function getGoogleAuthURL() {
  const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
  const options = {
    redirect_uri: 'https://socialscribe-v1-backend.onrender.com/auth/google/callback',
    client_id: process.env.GOOGLE_CLIENT_ID,
    access_type: "offline",
    response_type: "code",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ].join(" "),
  };

  return `${rootUrl}?${querystring.stringify(options)}`;
}

// Helper function to exchange code for tokens
async function getTokens({ code, clientId, clientSecret, redirectUri }) {
  const url = "https://oauth2.googleapis.com/token";
  const values = {
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  };

  return axios
    .post(url, querystring.stringify(values), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    })
    .then((res) => res.data)
    .catch((error) => {
      console.error("Failed to fetch auth tokens", error.message);
      throw new Error(error.message);
    });
}

// Getting login URL
app.get("/auth/google/url", (req, res) => {
  const googleAuthURL = getGoogleAuthURL();
  return res.redirect(googleAuthURL);
});
/**ENCRYPTION CODE HERE*********** */
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// Handling the callback from Google OAuth
app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code ;

  const { id_token, access_token } = await getTokens({
    code,
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: "https://socialscribe-v1-backend.onrender.com/auth/google/callback",
  });

  // Fetch the user's profile using the access token
  const googleUser = await axios
    .get(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
      {
        headers: {
          Authorization: `Bearer ${id_token}`,
        },
      }
    )
    .then((res) => res.data)
    .catch((error) => {
      console.error("Failed to fetch user data");
      throw new Error(error.message);
    });

  // Find or create a user in your database
  let user = await userdb.findOneAndUpdate(
    { googleId: googleUser.id },
    {
      googleId: googleUser.id,
      userName: googleUser.name,
      email: googleUser.email,
    },
    { new: true, upsert: true } // Create the user if not found
  );

  console.log("User found/created at MongoDB ::: " , user); 

  const token = jwt.sign(
    {
      id: user._id,
      googleId: user.googleId,
      email: user.email,
      isANewUser: user.isANewUser,
      userName : user.userName,
    },
    process.env.JWT_KEY,
    { expiresIn: "3 days" }
  );

  console.log("token generated at MongoDB ::: " , token); 

  // Derive key using PBKDF2
  const password = "kaif123";
  const salt = "salt123"; // Ensure this salt is known on both backend and frontend
  const key = deriveKey(password, salt);

  // Encrypt the token using AES-256-GCM
  const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  // Concatenate IV, authTag, and encrypted token
  const encryptedTokenWithIv = iv.toString('hex') + ':' + authTag + ':' + encrypted;

  // Redirect to the frontend with the encrypted token in the query parameters
  res.redirect(`https://socialscribe-aipoool.onrender.com/redirecting?token=${encodeURIComponent(encryptedTokenWithIv)}`);
});



// Testing routes
app.get("/auth/test", (req, res) => {
  res.json({ Hi: "This is the AUTH Route, after the edits have been made " });
});

app.get("/heavy" , (req, res) => {
  let total = 0; 
  for(let i=0 ; i< 50_000_000 ; i++){
    total++; 
  }
  res.send("Total: " + total); 
});

app.get("/auth/login/success", (req, res) => {
  // Extract the token from the cookies
  const token = req.cookies[process.env.COOKIE_KEY];

  if (!token) {
    // If no token is found, return a 401 Unauthorized error
    return res.status(401).json({ message: "Authentication token is missing" });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_KEY);
    return res.status(200).send(decoded);
  } catch (err) {
    console.log("JWT verification failed:", err.message);
    return res.status(401).json({ message: "Invalid authentication token" });
  }
});



app.post("/auth/userdata", verifyToken, async (req, res) => {
  const { id } = req.body;
  try {
      const user = await userdb.findById(id);
      console.log({ results: user });
      res.status(200).json({ results: user });
  } catch (error) {
    console.error("Error retrieving user data", error);
    res.status(500).send({ message: "Error retrieving user data" });
  }
});


app.post("/auth/logout", verifyToken, async (req, res, next) => {
  const { id } = req.body;
  const cacheKeys = [`user:${id}:counter`, `user:${id}:rating`];

  console.log(`Clearing cache for keys: ${cacheKeys.join(', ')}`);

  redisConnectionClient.del(cacheKeys);
  res.status(200).json({ success: true, message: 'Redis cache cleared successfully.' });
});

// Testing routes
app.get("/api/test", (req, res) => {
  res.json({ Hi: "This is the API Route" });
});

/**OPENAI API ROUTES */
app.options("/api/generate-response", cors());
app.post("/api/generate-response", verifyToken, async (req, res) => {
  const { post, tone,  site } = req.body;


  try {
    const comment = await postChatGPTMessage(post, tone,  site);
    res.json({ results: { comment } });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/setUserStatus", verifyToken, async (req, res) => {
  const { id } = req.body;
  console.log(req.body);

  try {
      const updatedUser = await userdb.findOneAndUpdate(
        { _id: id },
        { $set: { isANewUser: false } },
        { new: true, useFindAndModify: false }
      );
      res.send({ message: "User status updated successfully" });
  } catch (error) {
    console.error("Error updating Counter:", error);
    res.status(500).send({ message: "Error updating Counter" });
  }
});

app.post("/api/getUserRating", verifyToken, async (req, res) => {
  const { id } = req.body;
  const cacheKey = `user:${id}:rating`;
  try {
      const userRatingRedis = await redisConnectionClient.get(cacheKey);
      if (userRatingRedis) {
        const parsedData = JSON.parse(userRatingRedis); 
        console.log("Rating from the redis :: " , parsedData.userRating);
        res.status(200).json({ rating: parsedData.userRating });
      }else {
        const response = await userdb.findById(id);
        await redisConnectionClient.set(cacheKey, JSON.stringify(response));
        console.log("Rating set into redis with key :: ", cacheKey);
        res.status(200).json({ rating: response.userRating });
      }

  } catch (error) {
      res.status(500).send({ message: "Error retrieving user rating" });
  }
});


app.post("/api/setCounter", verifyToken, async (req, res) => {
  const { id, count } = req.body;
  const cacheKey = `user:${id}:counter`;
  console.log(req.body);

  try {
      const updatedUser = await userdb.findOneAndUpdate(
        { _id: id },
        { $set: { buttonCounts: count } },
        { new: true, useFindAndModify: false }
      );
      console.log("Updated User: ", updatedUser);

      // Update the Redis cache with the new counter value
      await redisConnectionClient.set(cacheKey, JSON.stringify(updatedUser));
      console.log(`Data updated in redis for key: ${cacheKey}`);

      res.send({ message: "Counter updated successfully" });
  } catch (error) {
    console.error("Error updating Counter:", error);
    res.status(500).send({ message: "Error updating Counter" });
  }
});

// redis version to get the counter 
// API to get counter with Redis caching
app.post("/api/getCounter", verifyToken, async (req, res) => {
  const { id } = req.body;
  const cacheKey = `user:${id}:counter`;
  try {
      // trying to get the data from redis 
      const userCountRedis = await redisConnectionClient.get(cacheKey);
      if (userCountRedis) {
        const parsedData = JSON.parse(userCountRedis);
        console.log("COUNTER GET from Redis :: : ", parsedData.buttonCounts);
        console.log("TOTAL COUNT from Redis :: : ", parsedData.totalCount);
        res.status(200).json({
          count: parsedData.buttonCounts,
          totalCount: parsedData.totalCount,
        });
      } 
      else {
        // if not , find in the db and set in redis 
        const response = await userdb.findById(id);
        console.log("COUNTER GET from db :: : ", response.buttonCounts);
        console.log("TOTAL COUNT from db :: : ", response.totalCount);

        // set the data in redis 
        await redisConnectionClient.set(cacheKey, JSON.stringify(response)); 
        console.log(`Data set in redis for key: ${cacheKey}`);

        res.status(200).json({
          count: response.buttonCounts,
          totalCount: response.totalCount,
        });
      }
  } catch (error) {
    console.error("Error getting Counter:", error);
    res.status(500).send({ message: "Error getting Counter" });
  }
});


/**WILL BE REMOVING ONCE THE CHANGES ARE BEING MADE COMPLETELY */
app.post("/api/check", async (req, res) => {
  const { key } = req.body;

  const openai = new OpenAI({ apiKey: key });

  try {
    const completion = await openai.chat.completions.create({
      messages: [{ role: "system", content: "Checking the key..." }],
      model: "gpt-3.5-turbo",
    });

    const isValid = completion?.choices[0]?.message?.content ? true : false;
    console.log(isValid);
    console.log({ isValid });
    res.status(200).json({ isValid });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ isValid: false });
  }
});

// app.post("/api/create-checkout-session", async (req, res) => {
//   /** ACCEPT THE EMAIL VIA BODY TO HARDCODE IT INTO THE PAYMENT BLANK */
//   const { data } = req.body;

//   const userEmail = data.userEmail;
//   const mongoId = data.userMongoId;
//   const typeOfPlan = data.type;
//   const StripeProductId = data.productId;
//   const StripePriceId = data.priceId;

//   let customer;
//   const auth0UserId = userEmail;
//   console.log("Data Here :::: ", data);
//   console.log(`${data.plan} ::::: ${data.price} :::::: ${mongoId}`);

//   /** CHECK IF THE CUSTOMER IS PRESENT IN THE STRIPE CUSTOMER'S LIST */
//   const existingCustomers = await stripe.customers.list({
//     email: userEmail,
//     limit: 1,
//   });

//   /** CHECK IF THERE IS SOME ACTIVE SUBSCRIPTION ALREADY */
//   if (existingCustomers.data.length > 0) {
//     // Customer already exists
//     customer = existingCustomers.data[0];

//     // Check if the customer already has an active subscription
//     const subscriptions = await stripe.subscriptions.list({
//       customer: customer.id,
//       status: "active",
//       limit: 1,
//     });

//     if (subscriptions.data.length > 0) {
//       // Customer already has an active subscription, send them to biiling portal to manage subscription

//       const stripeSession = await stripe.billingPortal.sessions.create({
//         customer: customer.id,
//         return_url: "https://socialscribe-aipoool.onrender.com/success",
//       });
//       //return res.status(409).json({ redirectUrl: stripeSession.url });

//       return res.json({ redirectUrl: stripeSession.url });
//     }
//   } else {
//     // No customer found, create a new one
//     customer = await stripe.customers.create({
//       email: userEmail,
//       metadata: {
//         userId: auth0UserId, // Replace with actual Auth0 user ID
//         mongoId: mongoId,
//         priceId: StripePriceId,
//         productId: StripeProductId,
//         type: typeOfPlan,
//       },
//     });
//   }

//   console.log(`Customer::::::`);
//   console.log(customer);

//   console.log("Customer ID ::: ", customer.id);

//   // const lineItems = [
//   //   {
//   //     price_data: {
//   //       currency: "inr",
//   //       product_data: {
//   //         name: data.plan,
//   //         description: `This is the ${data.plan} version.`,
//   //       },
//   //       unit_amount: data.price * 100,
//   //       recurring: {
//   //         interval: "month",
//   //       },
//   //     },
//   //     quantity: 1,
//   //   },
//   // ];

//   const lineItems = [
//     {
//       price: StripePriceId,
//       quantity: 1,
//     },
//   ];

//   const session = await stripe.checkout.sessions.create({
//     payment_method_types: ["card"],
//     line_items: lineItems,
//     billing_address_collection: "auto",
//     mode: "subscription",
//     success_url: "https://socialscribe-aipoool.onrender.com/success",
//     cancel_url: "https://socialscribe-aipoool.onrender.com/cancel",
//     metadata: {
//       userId: auth0UserId,
//       mongoId: mongoId,
//       priceId: StripePriceId,
//       productId: StripeProductId,
//       type: typeOfPlan,
//     },
//     customer: customer.id,
//   });

//   console.log("Session ID Here ::: ", session.id);

//   res.json({ id: session.id });
// });

// // webhook for subscription
// app.post("/stripe-webhook", async (req, res) => {
//   let event = req.body;

//   if (endptSecret) {
//     // Get the signature sent by Stripe
//     const signature = req.headers["stripe-signature"];
//     try {
//       event = stripe.webhooks.constructEvent(req.body, signature, endptSecret);
//       console.log("Event Type ::: ", event.type);
//     } catch (err) {
//       console.log(`⚠️  Webhook signature verification failed.`, err.message);
//       return res.sendStatus(400);
//     }
//   }

//   if (event.type === "invoice.payment_succeeded") {
//     const invoice = event.data.object;

//     // On payment successful, get subscription and customer details
//     const subscription = await stripe.subscriptions.retrieve(
//       event.data.object.subscription
//     );
//     const customer = await stripe.customers.retrieve(
//       event.data.object.customer
//     );

//     console.log(
//       `Subscription from the PAYMENT SUCCEEDED :::::: `,
//       subscription
//     );

//     if (invoice.billing_reason === "subscription_create") {
//       // Getting the mongoId from the metadata -

//       const mongoId = customer?.metadata?.mongoId;
//       const typeOfPlan = customer?.metadata?.type;
//       const priceId = customer?.metadata?.priceId;
//       const productId = customer?.metadata?.productId;

//       // calling the database and getting the totalcounts

//       let infoDB = await userdb.findById(mongoId);
//       let dbTotalCount = infoDB.totalCount;
//       console.log(dbTotalCount);
//       let updatePlanCount;
//       if (typeOfPlan === "premium") {
//         updatePlanCount = dbTotalCount + 10;
//       } else {
//         updatePlanCount = dbTotalCount + 30;
//       }
//       const result = await userdb.findOneAndUpdate(
//         { _id: mongoId },
//         {
//           $set: {
//             subId: event.data.object.subscription,
//             endDate: subscription.current_period_end * 1000,
//             totalCount: updatePlanCount,
//             subType: typeOfPlan,
//             stripePriceId: priceId,
//             stripeProductId: productId,
//           },
//         },
//         { new: true, useFindAndModify: false }
//       );

//       console.log(`A document was inserted with the invoice ID: ${invoice.id}`);
//       console.log(
//         `First subscription payment successful for Invoice ID: ${customer.email} ${customer?.metadata?.userId}`
//       );
//     } else if (
//       invoice.billing_reason === "subscription_cycle" ||
//       invoice.billing_reason === "subscription_update"
//     ) {
//       // Handle recurring subscription payments
//       console.log(
//         `Subscription from the RECURRING PAYMENT :::::: `,
//         subscription
//       );
//       console.log(`CHANGED PLAN HERE  :::::: `, subscription.plan);

//       const mongoId = customer?.metadata?.mongoId;
//       let updatePlanCount, typeOfPlan;
//       const priceId = subscription?.plan?.id;
//       const productId = subscription?.plan?.product;
//       // calling the database and getting the totalcounts
//       let infoDB = await userdb.findById(mongoId);
//       let dbTotalCount = infoDB.totalCount;

//       if (priceId === "price_1PKzSsSGYG2CnOjsDpM6cUau") {
//         updatePlanCount = dbTotalCount + 10;
//         typeOfPlan = "premium";
//       } else {
//         updatePlanCount = dbTotalCount + 30;
//         typeOfPlan = "pro";
//       }
//       const result = await userdb.findOneAndUpdate(
//         { _id: mongoId },
//         {
//           $set: {
//             endDate: subscription.current_period_end * 1000,
//             recurringSuccessful_test: true,
//             totalCount: updatePlanCount,
//             subType: typeOfPlan,
//             stripePriceId: priceId,
//             stripeProductId: productId,
//           },
//         },
//         { new: true, useFindAndModify: false }
//       );

//       if (result.matchedCount === 0) {
//         console.log("No documents matched the query. Document not updated");
//       } else if (result.modifiedCount === 0) {
//         console.log(
//           "Document matched but not updated (it may have the same data)"
//         );
//       } else {
//         console.log(`Successfully updated the document`);
//       }

//       console.log(
//         `Recurring subscription payment successful for Invoice ID: ${invoice.id}`
//       );
//     }

//     console.log(
//       new Date(subscription.current_period_end * 1000),
//       subscription.status,
//       invoice.billing_reason
//     );
//   }

//   // For canceled/renewed subscription
//   if (event.type === "customer.subscription.updated") {
//     const subscription = event.data.object;

//     const customer = await stripe.customers.retrieve(
//       event.data.object.customer
//     );
//     console.log(subscription); 
//     console.log(subscription.cancel_at_period_end);

//     // console.log(event);
//     if (subscription.cancel_at_period_end) {
//       console.log(`Subscription ${subscription.id} was canceled.`);
//       const mongoId = customer?.metadata?.mongoId;

//       // await stripe.subscriptions.update(subscription.id, {
//       //   cancel_at_period_end: true,
//       // });

//       const result = await userdb.findOneAndUpdate(
//         {
//           _id: mongoId,
//         },
//         {
//           $unset: {
//             endDate: "",
//             subId: "",
//             recurringSuccessful_test: false,
//             stripePriceId: "",
//             stripeProductId: "",
//           },
//           $set: {
//             subType: "free",
//             hasCancelledSubscription: true,
//           },
//         }
//       );

//       console.log("Customer from CANCEL SUBSCRIPTION :::: ", customer); // we're getting the data
//       console.log("Subscription after CANCEL SUBSCRIPTION :::: ", subscription); // we're getting
      
//     } else {
//       ///calling the database and getting the totalcounts
//       const mongoId = customer?.metadata?.mongoId;
//       let infoDB = await userdb.findById(mongoId);
//       let dbTotalCount = infoDB.totalCount;
//       let hasCancelledSubscription = infoDB.hasCancelledSubscription;
//       console.log("Has cancelled plan ::: " , hasCancelledSubscription); 

//       if (hasCancelledSubscription) {
//         const subscriptionsUpdated = await stripe.subscriptions.list({
//           customer: customer.id,
//         });

//         console.log(
//           "Subscription plan ::: ",
//           subscriptionsUpdated.data[0].plan
//         );
//         console.log(customer?.metadata);

//         const priceId = subscriptionsUpdated.data[0].plan?.id;
//         const productId = subscriptionsUpdated.data[0].plan?.product;

//         console.log(`Original details ::::: ${customer?.metadata.priceId} --> 
//         ${customer?.metadata.productId} --> ${customer?.metadata.type}`);

//         console.log("Customer from RESTARTED SUBSCRIPTION :::: ", customer); // we're getting the data

//         let updatePlanCount, typeOfPlan;
//         if (priceId === "price_1PKzSsSGYG2CnOjsDpM6cUau") {
//           updatePlanCount = dbTotalCount + 10;
//           typeOfPlan = "premium";
//         } else {
//           updatePlanCount = dbTotalCount + 30;
//           typeOfPlan = "pro";
//         }

//         console.log(`Changed to details ::::: ${priceId} -->
//       ${productId} --> ${typeOfPlan}`);

//         const result = await userdb.findOneAndUpdate(
//           { _id: mongoId },
//           {
//             $set: {
//               endDate: subscription.current_period_end * 1000, // need to check this!!!
//               recurringSuccessful_test: true,
//               totalCount: updatePlanCount,
//               subType: typeOfPlan,
//               stripePriceId: priceId,
//               stripeProductId: productId,
//               hasCancelledSubscription: false,
//             },
//           },
//           { new: true, useFindAndModify: false }
//         );
//       }
//     }
//   }

//   res.status(200).end();
// });



// Testing routes
app.get("/test", (req, res) => {
  res.json({ Hi: "This is a... testing message" });
});



// getting the clustering code here 
// normal clustering without round-robin

if (cluster.isPrimary) {
  // Limit the number of workers to 2 due to resource constraints

  /** NOTE : WE CAN LIMIT THE NUMBER OF WORKERS IN THE FOLLOWING MANNER - 
   * 
   * const numWorkers = Math.min(2, os.cpus().length);
   * 
   * FOR NOW , WE SHALL GO TO THE MAX WORKERS
   */
  const numWorkers = Math.min(3, os.cpus().length);

  console.log(`Master ${process.pid} is running`);
  console.log(`Forking ${numWorkers} workers...`);

  for (let i = 0; i < numWorkers; i++) {
      cluster.fork();
  }

  // The of the number of cores 
  console.log(`Available CPUs: ${numWorkers}`) ;

  cluster.on("online",(worker, code, signal) => { 
      console.log(`worker ${worker.process.pid} is online`); 
  }); 

  cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died`);
      console.log('Forking a new worker...');
      cluster.fork();
  });
} else {
  const PORT = process.env.PORT || 1997;

  app.listen(PORT, () => {
    console.log(
      `${chalk.green.bold("✅")} 👍Server running in ${chalk.yellow.bold(
        process.env.NODE_ENV
      )} mode on port ${chalk.blue.bold(PORT)}`
    );
  });
}



