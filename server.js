const express = require('express');
const mongoose = require ('mongoose');
const authRoutes = require('./routes/auth');

const app = express();
const port = 5000;

const uri = 'mongodb+srv://gabriel15:Caminando65@cluster0.z1ctu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(uri)
	.then(() => console.log('MongoDB connected succesfully'))
	.catch(err => console.error('MongoDB connection error:', err));

app.use(express.json());
app.use('/api/auth', authRoutes);

app.listen(port, () =>{
	console.log(`Server is running on http://localhost:${port}`);
});
