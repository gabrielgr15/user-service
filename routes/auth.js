const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const jwt = require('jsonwebtoken')
const config = require('config')
const crypto = require('crypto')
const RefreshToken = require('../models/RefreshToken')
const {generateTokens} = require('../utils/tokenUtils')
const auth = require('../middleware/auth')

const router = express.Router();

router.post(
  '/register',
  [
    body('username', 'Username is required').notEmpty().trim(),
    body('email', 'Please include a valid email').isEmail().normalizeEmail(),
    body('password', 'Password is required').notEmpty().isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ error: 'User already exists'  });
}
      user = new User({
        username,
        email,
        password
})
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

        await user.save();
	const { accessToken, refreshToken } = await generateTokens(user)
	return res.status(201).json({accessToken, refreshToken })
}
	catch (err) {
	console.error(err);
      	res.status(500).send('Server error');
}
})



router.post(
	'/login',
	[
	body('email', 'The email is incorrect').notEmpty().isEmail().normalizeEmail(),
	body('password', 'The password is incorrect').notEmpty(),
	],
	async (req, res) => {
	const errors = validationResult(req)
	if(!errors.isEmpty()){
		return res.status(400).json({ errors : errors.array() })
}
	const  { email, password } = req.body;

	try {
	const user = await User.findOne({email})
	if (!user){
		return res.status(400).send('This email does not  exist')
}
	isMatch = await bcrypt.compare(password, user.password)
	if (!isMatch){
		return res.status(400).json({errors : [{ msg : 'Incorrect password'}] })
}
	console.log(user)
	const { accessToken, refreshToken } = await generateTokens(user._id)
	console.log('accessToken:', accessToken)
	console.log('refreshToken:', refreshToken)
	return res.status(200).json({accessToken, refreshToken});
}
	catch (err){
                console.error(err)
		console.error(err.message)
                res.status(500).json({error : 'server error:', err})
}})


router.post(
	'/refresh',
	auth,
	[
	body('token', 'Refresh token is required').trim().notEmpty().isString(),
	],
	async (req, res) => {
	const errors = validationResult(req)
	if (!errors.isEmpty()){
	res.status(400).json({error: errors.array })
}	try{
	const {token} = req.body
	storedToken = await RefreshToken.findOne({token})
	if (!storedToken || storedToken.token !== token){
	res.status(404).json({error : 'Invalid token'})
}	const user = storedToken.user
	await RefreshToken.findByIdAndDelete(storedToken-_id)
	const {refreshToken, accessToken} = await generateTokens(user)
	res.status(200).json({refreshToken, accessToken})
}	catch(err){
	res.status(500).json({error : 'Internal server error', err})
}})

router.post(
	'/verify',
	[
	body('token','Requires a token').trim().notEmpty()
	],
	async (req, res) => {
	const errors = validationResult(req)
	if (!errors.isEmpty()){
	return res.status(400).json({error : 'Requires a token'})
}	try{
	const {token} = req.body
	const verified = jwt.verify(token, config.get('jwtSecret'))
	const user = verified.user
	return res.status(200).json({userId : user.id  })
}	catch (err){
	return res.status(401).json({error: 'Invalid token'})
}})




module.exports = router;
