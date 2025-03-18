const express = require('express');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Store active authentication flows
const authFlows = {};

// GET /authorize - Initiate Authentication
app.get('/authorize', (req, res) => {
  const { response_type, client_id, response_mode, redirect_uri, scope, state } = req.query;
  
  // Validate required parameters
  if (!response_type || response_type !== 'code' || !client_id || !response_mode || response_mode !== 'direct' || !redirect_uri) {
    return res.status(400).json({
      code: 'ABA-40000',
      message: 'Invalid request parameters',
      description: 'Missing or invalid required parameters',
      traceId: uuidv4()
    });
  }
  
  // Create a new authentication flow
  const flowId = uuidv4();
  
  // Store flow information
  authFlows[flowId] = {
    clientId: client_id,
    redirectUri: redirect_uri,
    state: state || '',
    scope: scope || 'openid',
    status: 'INCOMPLETE',
    step: 'initial'
  };
  
  // Respond with authentication options
  res.status(200).json({
    flowId: flowId,
    flowStatus: 'INCOMPLETE',
    flowType: 'AUTHENTICATION',
    nextStep: {
      stepType: 'AUTHENTICATOR_PROMPT',
      authenticators: [
        {
          authenticatorId: 'QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM',
          authenticator: 'Username & Password',
          idp: 'LOCAL',
          metadata: {
            i18nKey: 'authenticator.basic',
            promptType: 'USER_PROMPT',
            params: [
              {
                param: 'username',
                type: 'STRING',
                isConfidential: false,
                order: 1,
                validationRegex: '^[\\S]{3,50}$',
                i18nKey: 'param.username'
              },
              {
                param: 'password',
                type: 'STRING',
                isConfidential: true,
                order: 2,
                i18nKey: 'param.password'
              }
            ]
          },
          requiredParams: ['username', 'password']
        }
      ]
    },
    links: [
      {
        name: 'authentication',
        href: '/authn',
        method: 'POST'
      }
    ]
  });
});

// POST /authn - Handle Authentication
app.post('/authn', (req, res) => {
  const { flowId, selectedAuthenticator } = req.body;
  
  // Validate request
  if (!flowId || !selectedAuthenticator || !selectedAuthenticator.authenticatorId) {
    return res.status(400).json({
      code: 'ABA-40001',
      message: 'Invalid authentication request',
      description: 'Missing required parameters in request body',
      traceId: uuidv4()
    });
  }
  
  // Check if flow exists
  const flow = authFlows[flowId];
  if (!flow) {
    return res.status(400).json({
      code: 'ABA-40002',
      message: 'Invalid flow ID',
      description: 'The provided flow ID does not exist or has expired',
      traceId: uuidv4()
    });
  }
  
  // Handle basic authentication
  if (selectedAuthenticator.authenticatorId === 'QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM') {
    const { username, password } = selectedAuthenticator.params || {};
    
    // Simple mock authentication logic
    if (username === 'admin' && password === 'admin') {
      // Successful authentication
      const authCode = uuidv4();
      
      // Update flow status
      authFlows[flowId].status = 'SUCCESS_COMPLETED';
      
      return res.status(200).json({
        flowStatus: 'SUCCESS_COMPLETED',
        authData: {
          code: authCode,
          state: flow.state
        }
      });
    } else {
      // Failed authentication
      return res.status(200).json({
        flowId: flowId,
        flowStatus: 'FAIL_INCOMPLETE',
        flowType: 'AUTHENTICATION',
        nextStep: {
          stepType: 'AUTHENTICATOR_PROMPT',
          authenticators: [
            {
              authenticatorId: 'QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM',
              authenticator: 'Username & Password',
              idp: 'LOCAL',
              metadata: {
                i18nKey: 'authenticator.basic',
                promptType: 'USER_PROMPT',
                params: [
                  {
                    param: 'username',
                    type: 'STRING',
                    isConfidential: false,
                    order: 1,
                    validationRegex: '^[\\S]{3,50}$',
                    i18nKey: 'param.username'
                  },
                  {
                    param: 'password',
                    type: 'STRING',
                    isConfidential: true,
                    order: 2,
                    i18nKey: 'param.password'
                  }
                ]
              },
              requiredParams: ['username', 'password']
            }
          ],
          messages: [
            {
              type: 'ERROR',
              messageId: 'msg_invalid_un_pw',
              message: 'Invalid username or password.',
              i18nKey: 'message.msg_invalid_un_pw',
              context: [
                {
                  key: 'remainingAttempts',
                  value: '2'
                }
              ]
            }
          ]
        },
        links: [
          {
            name: 'authentication',
            href: '/authn',
            method: 'POST'
          }
        ]
      });
    }
  } else {
    // Unsupported authenticator
    return res.status(400).json({
      code: 'ABA-40003',
      message: 'Unsupported authenticator',
      description: 'The provided authenticator is not supported',
      traceId: uuidv4()
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`WSO2 Auth Mock Service running on port ${port}`);
});



