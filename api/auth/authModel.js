require("dotenv").config();

const { dynamoDB } = require('../../config/awsConfig');
const { QueryCommand, PutItemCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const TABLE_NAME = process.env.DYNAMODB_TABLE_NAME;

// Find User by Email or Phone
exports.findUserByEmailOrPhone = async (email, phone) => {
    const identifier = email || phone;
    const params = {
        TableName: TABLE_NAME,
        KeyConditionExpression: 'usersPartitionkey = :identifier AND usersSortKey = :sortKey',
        ExpressionAttributeValues: {
            ':identifier': { S: identifier },
            ':sortKey': { S: 'user' },
        },
    };

    const command = new QueryCommand(params);
    const result = await dynamoDB.send(command);
    return result.Items && result.Items[0];
};

// Create User with OTP
exports.createUser = async (user) => {
    const params = {
        TableName: TABLE_NAME,
        Item: {
            usersPartitionkey: { S: user.email || user.phone },
            usersSortKey: { S: 'user' },
            email: { S: user.email || '' },
            phone: { S: user.phone || '' },
            otp: { S: user.otp || '' },
            otpExpiry: { S: user.otpExpiry.toISOString() },
        },
    };
    const command = new PutItemCommand(params);
    await dynamoDB.send(command);
};

// Update User
exports.updateUser = async (identifier, updateExpression, expressionValues) => {
    const params = {
        TableName: TABLE_NAME,
        Key: {
            usersPartitionkey: { S: identifier },
            usersSortKey: { S: 'user' },
        },
        UpdateExpression: updateExpression,
        ExpressionAttributeValues: expressionValues,
    };

    const command = new UpdateItemCommand(params);
    await dynamoDB.send(command);
};
