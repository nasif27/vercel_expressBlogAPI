// Boilerplate code
const express = require("express"); // importing Express framework
// let path = require("path");
const cors = require("cors");
const { Pool } = require("pg"); // Destructure Pool class from Postgres (pg)
// const { DATABASE_URL, SECRET_KEY } = process.env;
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const { error } = require("console");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    require: true,
  },
});

// get Postgres version used
async function getPostgresVersion() {
  const client = await pool.connect();
  try {
    const response = await client.query("SELECT version()");
    console.log(response.rows[0]); // DB response will be returned in the form of object array {[]}
  } finally {
    client.release();
  }
}

getPostgresVersion();

// Endpoint code
/////////////////////////////////////// AUTH ENDPOINT ///////////////////////////////////////

// signUp endpoint
app.post("/signup", async (req, res) => {
  const client = await pool.connect();

  try {
    // destructure user info from request body
    const { username, email, password } = req.body;
    // hashing pwd with cost factor of 12. Hash is a Bcrypt function
    const hashedPassword = await bcrypt.hash(password, 12);
    const userExists = await client.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email],
    );
    // const usernameExists = await client.query("SELECT * FROM users WHERE username = $1", [username]);
    // const emailExists = await client.query("SELECT * FROM users WHERE email = $1", [email]);

    // if user that want to be registered exists, return error
    if (userExists.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Username or email already exist" });
    }

    // if not exists yet, proceed to register the user
    await client.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword],
    );
    res.status(200).json({ message: "User has been registered successfully" });
  } catch (error) {
    console.log("Error:", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  } finally {
    client.release();
  }
});

// sign in endpoint
app.post("/signin", async (req, res) => {
  const client = await pool.connect();
  const { username, email } = req.body;

  try {
    // 1. check username & email
    const userExist = await client.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email],
    );
    // if user exist, store in a variable
    const user = userExist.rows[0];
    // 2. if registered user not found, return error to client
    if (!user) {
      return res.status(400).json({ message: "Incorrect username or email" });
    }

    // 3. verify password by comparing between pwd in request body & pwd exist in DB
    const passwordIsValid = await bcrypt.compare(
      req.body.password,
      user.password, // hashed pwd
    );
    // if invalid password, return error to client & set token to null
    if (!passwordIsValid) {
      return res.status(400).json({ auth: false, token: null });
    }
    // if valid password, pass 3 arguments to jwt.sign() method to generate JWT token
    var token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      SECRET_KEY,
      { expiresIn: 86400 },
    );
    // after JWT token has been generated, return response to client
    res.status(200).json({ auth: true, token: token });
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  } finally {
    client.release();
  }
});

// get username --endpoint
app.get("/username", (req, res) => {
  // check if Authorization Bearer token was provided
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(400).json({ error: "Access denied" });
  }

  try {
    // Verify the token & fetch the user info
    const verifiedToken = jwt.verify(authToken, SECRET_KEY);
    // fetch username from token & return response to client
    res.json({ username: verifiedToken.username });
  } catch (error) {
    // if invalid token, return error
    res.status(400).json({ error: "Invalid token" });
  }
});

/////////////////////////////////////// REQUEST ENDPOINT ///////////////////////////////////////

// Get all posts --endpoint
app.get("/posts", async (req, res) => {
  const client = await pool.connect();

  try {
    const posts = await client.query("SELECT * FROM posts");
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "All posts not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  }
});

// Get all posts (WITH USERNAME) --endpoint
app.get("/postss", async (req, res) => {
  const client = await pool.connect();

  try {
    const posts = await client.query(
      "SELECT posts.id, posts.user_id, posts.title, posts.content, posts.created_at, posts.updated_at, users.username FROM posts INNER JOIN users ON posts.user_id = users.id",
    );
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "All posts not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  }
});

// Get specific post based on post id --endpoint
app.get("/posts/:id", async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    const posts = await client.query("SELECT * FROM posts WHERE id = $1", [id]);
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "Post with that id is not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Get specific post (WITH USERNAME) based on post id --endpoint
app.get("/postss/:id", async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    const posts = await client.query(
      "SELECT posts.id, posts.user_id, posts.title, posts.content, posts.created_at, posts.updated_at, users.username FROM posts INNER JOIN users ON posts.user_id = users.id WHERE posts.id = $1",
      [id],
    );
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "Post with that id is not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Get current title
app.get("/postTitle/:id", async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    const postTitle = await client.query(
      "SELECT title FROM posts WHERE id = $1",
      [id],
    );
    if (postTitle.rowCount > 0) {
      res.json(postTitle.rows[0].title);
    } else {
      res.status(404).json({ error: "Post title with that id is not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Get current content
app.get("/postContent/:id", async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    const postContent = await client.query(
      "SELECT content FROM posts WHERE id = $1",
      [id],
    );
    if (postContent.rowCount > 0) {
      res.json(postContent.rows[0].content);
    } else {
      res.status(404).json({ error: "Post content with that id is not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Get all posts from specific user --endpoint
app.get("/posts/user/:user_id", async (req, res) => {
  const { user_id } = req.params;
  const client = await pool.connect();

  try {
    const posts = await client.query("SELECT * FROM posts WHERE user_id = $1", [
      user_id,
    ]);
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "No post found for this user" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Get all posts from specific user (WITH USERNAME) --endpoint
app.get("/postss/user/:user_id", async (req, res) => {
  const { user_id } = req.params;
  const client = await pool.connect();

  try {
    const posts = await client.query(
      "SELECT posts.id, posts.user_id, posts.title, posts.content, posts.created_at, posts.updated_at, users.username FROM posts INNER JOIN users ON posts.user_id = users.id WHERE posts.user_id = $1",
      [user_id],
    );
    if (posts.rowCount > 0) {
      // checking existence of row for 'posts' table
      res.json(posts.rows);
    } else {
      res.status(404).json({ error: "No post found for this user" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to html
  } finally {
    client.release();
  }
});

// Post endpoint
app.post("/posts", async (req, res) => {
  const { user_id, title, content } = req.body;
  const client = await pool.connect();

  try {
    // Check if user exists
    const userExists = await client.query(
      "SELECT id FROM users WHERE id = $1",
      [user_id],
    );

    if (userExists.rows.length > 0) {
      // post to DB & get the response (result)
      const post = await client.query(
        "INSERT INTO posts (user_id, title, content, created_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING *",
        [user_id, title, content],
      );
      // send response from DB (new post) to client
      res.json(post.rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  } finally {
    client.release();
  }
});

// Update specific post --endpoint
app.put("/posts/:id", async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  const client = await pool.connect();

  try {
    const updatedPost = await client.query(
      "UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *",
      [title, content, id],
    );
    res.json(updatedPost.rows[0]);
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  } finally {
    client.release();
  }
});

// Delete specific post --endpoint
app.delete("/posts/:id", async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    await client.query("DELETE FROM posts WHERE id = $1", [id]);
    res.json({ message: "The item has been deleted successfully" });
  } catch (error) {
    console.log("Error", error.message); // return error message to console
    res.status(500).json({ error: error.message }); // return error message to client
  } finally {
    client.release();
  }
});

// Boilerplate code
app.get("/", (req, res) => {
  res.status(200).json({ message: "welcome to blog app api" });
});

app.listen(PORT, () => {
  console.log(`App is listening on port ${PORT}`);
});
