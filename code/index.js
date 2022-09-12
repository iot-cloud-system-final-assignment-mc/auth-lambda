const AWS = require('aws-sdk');
const jwt_decode = require("jwt-decode");


function buildPolicy(principalId, effect, resource) {
    const authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
}

module.exports.handler = async (event, context) => {
    let authResponse = {};
    const auth = event.authorizationToken;
    if(!auth.includes('Bearer')) {
        authResponse = buildPolicy('user', 'Deny', event.methodArn); 
    } else {
        const token = auth.split(' ')[1];
        const payload = jwt_decode(token);
        console.log(payload);
        authResponse = buildPolicy(payload["cognito:username"], 'Allow', event.methodArn);
        authResponse.context = {
            username: payload["cognito:username"],
            email: payload["email"],
            isAdmin: payload["cognito:groups"].includes("SystemAdmins")
        };
    }

    return authResponse;
}
    // END
