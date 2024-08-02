module.exports = {
  apps: [
    {
      name: 'socialscribe_pm2',
      script: './server.js', // Replace with your app's entry point
      instances: 3,          // Or a number of instances
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
      },
      env_production: {
        NODE_ENV: 'production',
      }
    }
  ]
};
