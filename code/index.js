const AWS = require('aws-sdk');

module.exports.handler = async (event, context) => {
    console.log(event);
    console.log(context);
    return "OK";
}
    // END
