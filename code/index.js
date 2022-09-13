const AWS = require('aws-sdk');
const jwt_decode = require("jwt-decode");


function buildPolicy(principalId, effect, resource) {
    const authResponse = {};
    const splittedMethodArn = resource.split(':');
    const methodArnArray = splittedMethodArn[5].split('/');
    const region = splittedMethodArn[3];
    const awsAccountId = splittedMethodArn[4];
    const restApiId = methodArnArray[0];
    const stage = methodArnArray[1];
    const methods = [
        "GET/products",
        "POST/product",
        "GET/orders",
        "POST/order",
    ];

    authResponse.principalId = principalId;
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    for(let method of methods) {
        const statement = {};
        statement.Action = 'execute-api:Invoke';
        statement.Effect = effect;
        statement.Resource = `arn:aws:execute-api:${region}:${awsAccountId}:${restApiId}/${stage}/${method}`;
        policyDocument.Statement.push(statement);
    }
    authResponse.policyDocument = policyDocument;
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
        authResponse = buildPolicy(payload["cognito:username"], 'Allow', event.methodArn);
        authResponse.context = {
            username: payload["cognito:username"],
            email: payload["email"],
            isAdmin: payload["cognito:groups"] && payload["cognito:groups"].includes("SystemAdmins") || false
        };
    }

    return authResponse;
}
    // END
