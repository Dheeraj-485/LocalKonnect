require("dotenv").config();
const bcrypt=require("bcryptjs")
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
            role:{S:user.role},
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

// exports.createAdmin = async (req, res) => {
//     try {
//         const { secretKey, email, password } = req.body;

//         // Verify the secret key
//         if (secretKey !== process.env.ADMIN_CREATION_SECRET) {
//             return res.status(403).json({ message: 'Unauthorized access' });
//         }

//         // Hash the provided password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         const params = {
//             TableName: TABLE_NAME,
//             Item: {
//                 usersPartitionkey: { S: email },
//                 usersSortKey: { S: "user" },
//                 email: { S: email },
//                 role: { S: "Admin" },
//                 password: { S: hashedPassword }
//             },
//         };

//         await dynamoDB.send(new PutItemCommand(params));
//         res.status(200).json({ message: "Admin account created successfully" });
//     } catch (error) {
//         console.error("Error creating admin account: ", error);
//         res.status(500).json({ message: "Server error", error: error.message });
//     }
// };

require("dotenv").config();


const createAdmin = async () => {
    try {
        // const email = process.env.ADMIN_EMAIL;
        // const plainPassword = process.env.ADMIN_PASSWORD;
        const email = "createadmin@gmail.com";
        const plainPassword = "12345678";

        const hashedPassword = await bcrypt.hash(plainPassword, 10);

        const params = {
            TableName: TABLE_NAME,
            Item: {
                usersPartitionkey: { S: email },  
                usersSortKey: { S: 'user' },      
                email: { S: email },
                role: { S: 'Admin' },
                password: { S: hashedPassword }
            },
        };

        const command=new PutItemCommand(params)

        await dynamoDB.send(command);
        console.log('Admin account created successfully.');
    } catch (error) {
        console.error('Error creating admin account:', error.message);
    }
};

createAdmin();
