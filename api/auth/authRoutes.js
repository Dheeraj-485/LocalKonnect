const express = require('express');
const router = express.Router();
const authController = require('../auth/authController');
const { createAdmin } = require('./authModel');

router.post('/signup', authController.signup);
router.post('/verifyOTP', authController.verifyOTP);
router.post('/resendOTP', authController.resendOTP);
router.post('/createPassword', authController.createPassword);
router.post('/login', authController.login);
router.post("/forgetPassword",authController.forgetPassword);
router.post("/logout",authController.logout);


router.post("/createEmployee",authController.createEmployee);
// router.post("/createadmin",createAdmin)
module.exports = router;
