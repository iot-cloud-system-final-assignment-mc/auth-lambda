const jwt_decode = require("jwt-decode");

const denied_methods = [
    {
        path: "GET/products",
        effect: "Deny"
    },
    {
        path: "POST/product",
        effect: "Deny"
    },
    {
        path: "DELETE/product/*",
        effect: "Deny"
    },
    {
        path: "GET/orders",
        effect: "Deny"
    },
    {
        path: "POST/order",
        effect: "Deny"
    },
    {
        path: "DELETE/order/*",
        effect: "Deny"
    }
];

const user_methods = [
    {
        path: "GET/products",
        effect: "Allow"
    },
    {
        path: "POST/product",
        effect: "Deny"
    },
    {
        path: "DELETE/product/*",
        effect: "Deny"
    },
    {
        path: "GET/orders",
        effect: "Allow"
    },
    {
        path: "POST/order",
        effect: "Allow"
    },
    {
        path: "DELETE/order/*",
        effect: "Deny"
    }
];

const admin_methods = [
    {
        path: "GET/products",
        effect: "Allow"
    },
    {
        path: "POST/product",
        effect: "Allow"
    },
    {
        path: "DELETE/product/*",
        effect: "Allow"
    },
    {
        path: "GET/orders",
        effect: "Allow"
    },
    {
        path: "POST/order",
        effect: "Allow"
    },
    {
        path: "DELETE/order/*",
        effect: "Allow"
    }
];


function buildPolicy(principalId, methods, resource) {
    const authResponse = {};
    const splittedMethodArn = resource.split(':');
    const methodArnArray = splittedMethodArn[5].split('/');
    const region = splittedMethodArn[3];
    const awsAccountId = splittedMethodArn[4];
    const restApiId = methodArnArray[0];
    const stage = methodArnArray[1];



    authResponse.principalId = principalId;
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    for (let method of methods) {
        const statement = {};
        statement.Action = 'execute-api:Invoke';
        statement.Effect = method.effect;
        statement.Resource = `arn:aws:execute-api:${region}:${awsAccountId}:${restApiId}/${stage}/${method.path}`;
        policyDocument.Statement.push(statement);
    }
    authResponse.policyDocument = policyDocument;
    return authResponse;
}

module.exports.handler = async (event, context) => {
    let authResponse = {};
    try {
        const auth = event.authorizationToken;
        if (!auth.includes('Bearer')) {
            throw new Error('Invalid token');
        } else {
            const token = auth.split(' ')[1];
            const payload = jwt_decode(token);
            const context = {
                username: payload["cognito:username"],
                email: payload["email"],
                isAdmin: payload["cognito:groups"] && payload["cognito:groups"].includes("SystemAdmins") || false
            };
            allowed_methods = context.isAdmin ? admin_methods : user_methods;
            authResponse = buildPolicy(payload["cognito:username"], allowed_methods, event.methodArn);
            authResponse.context = context;
        }
    } catch (e) {
        console.log(e);
        authResponse = buildPolicy('user', denied_methods, event.methodArn);
    }

    return authResponse;
}
    // END
