// Retrieve the API key from the environment variable
const apiKey = pm.environment.get('apiKey');

// Check if the API key is available
if (!apiKey) {
  console.error('API_Key environment variable is not set.');
  // Optionally, you can abort the request if the API key is missing
  postman.setNextRequest(null);
} else {
  // Define the Tyk Gateway reload endpoint using the baseUrl
  const tykGatewayReloadUrl = `${pm.variables.get('baseUrl')}/tyk/reload?block=true`;

  // Send a GET request to the reload endpoint with the API key in the header
  pm.sendRequest({
    url: tykGatewayReloadUrl,
    method: 'GET',
    header: {
      'x-tyk-authorization': apiKey
    }
  }, function (err, res) {
    if (err) {
      console.error('Error reloading Tyk Gateway:', err);
    } else {
      console.log('Tyk Gateway reload response:', res.status);
    }
  });
}
