/* Load the local API schema and keep Try it out on the current server. */
'use strict';
window.addEventListener('DOMContentLoaded', () => {
  window.ui = SwaggerUIBundle({
    url: '/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    displayRequestDuration: true,
    defaultModelsExpandDepth: 1,
    validatorUrl: null,
    persistAuthorization: false,
    supportedSubmitMethods: ['get', 'post'],
    presets: [SwaggerUIBundle.presets.apis],
  });
});
