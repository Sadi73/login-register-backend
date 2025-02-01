const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');
require("dotenv").config();
const port = process.env.PORT || 5000;;

app.use(express.json());
app.use(cors());

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.jcb8og7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});
async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const database = client.db("simple-login");
        const userCollection = database.collection("userCollection");


        app.post('/login', async (req, res) => {
            try {
                const { provider } = req.query;
                const { email, password, name, picture, given_name, family_name } = req.body;

                if (!email) {
                    return res.status(400).json({ error: "Email is required." });
                }

                let user = await userCollection.findOne({ email });

                if (provider) {
                    if (!user) {
                        user = {
                            firstName: given_name,
                            lastName: family_name,
                            email,
                            username: email,
                            role: 'user',
                            provider,
                            createdAt: new Date()
                        };
                        // Assuming userCollection.insertOne() if needed for new users
                        await userCollection.insertOne(user);
                    }
                } else {
                    if (!password) {
                        return res.status(400).json({ error: "Password is required." });
                    }
                    if (!user) {
                        return res.status(404).json({ error: "User not found." });
                    }

                    const isPasswordValid = await bcrypt.compare(password, user.password);
                    if (!isPasswordValid) {
                        return res.status(401).json({ error: "Invalid credentials." });
                    }
                    delete user.password; // Remove password before sending response
                }

                const token = jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn: '1h' });
                res.status(200).json({ message: "Login successful", userDetails: { ...user, token } });

            } catch (error) {
                console.error("Login error:", error);
                res.status(500).json({ error: "Internal server error." });
            }
        });

        app.post('/register', async (req, res) => {
            try {
                const newUserData = req.body;

                const existingUser = await userCollection.findOne({ email: newUserData?.email });
                if (existingUser) {
                    return res.status(409).send({ success: false, message: 'User already exists' });
                };

                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(newUserData?.password, saltRounds);

                const finalData = {
                    ...newUserData,
                    username: newUserData?.email,
                    password: hashedPassword,
                    role: 'user',
                    createdAt: new Date()
                };

                const result = await userCollection.insertOne(finalData);
                if (result?.insertedId) {
                    return res.status(201).send({ success: true, message: 'User registered successfully' });
                } else {
                    return res.status(500).send({ success: false, message: 'User registration failed' });
                }
            } catch (error) {
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });


        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})