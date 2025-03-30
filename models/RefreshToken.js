const mongoose = require('mongoose')

const TokenSchema = new mongoose.Schema({
	token : {
	required: true,
	type: String,
	trim : true
},
	user: {
	type: mongoose.Schema.Types.ObjectId,
	ref : 'User',
	required: true
},
	createdAt:{
	type: Date,
	default: Date.now
},
	expiresAt : {
	type: Date,
	required: true,
}
})
module.exports = mongoose.model('RefreshToken', TokenSchema)
