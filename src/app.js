const express = require("express")
const bcrypt = require("bcrypt")
const app = express()
require("dotenv").config()
const mysql = require("mysql")
const generateAccessToken = require("./utils/createToken")
app.use(express.json())

const DB_HOST = process.env.DB_HOST
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_DATABASE = process.env.DB_DATABASE
const DB_PORT = process.env.DB_PORT
const PORT = process.env.PORT

const db = mysql.createPool({
  connectionLimit: 100,
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_DATABASE,
  port: DB_PORT
})

app.post("/createUser", async (req, res) => {
  const user = req.body.name;
  const email = req.body.email;
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  db.getConnection(async (err, connection) => {
    if (err) throw (err)
    const sqlSearch = "SELECT * FROM singup WHERE email = ?"
    const search_query = mysql.format(sqlSearch, [email])
    const sqlInsert = "INSERT INTO singup VALUES (0,?,?,?)"
    const insert_query = mysql.format(sqlInsert, [user, email, hashedPassword])
    await connection.query(search_query, async (err, result) => {
      if (err) throw (err)
      console.log("------> Search Results")
      console.log(result.length)
      if (result.length != 0) {
        connection.release()
        console.log("------> Email already exists")
        res.status(409)
        res.json("User already exists")
      }
      else {
        await connection.query(insert_query, (err, result) => {
          connection.release()
          if (err) throw (err)
          console.log("--------> Created new User")
          console.log(result.insertId)
          res.status(201)
          res.json("User has been created")
        })
      }
    })
  })
})


app.post("/login", (req, res) => {
  const email = req.body.email
  const password = req.body.password
  db.getConnection(async (err, connection) => {
    if (err) throw (err)
    const sqlSearch = "Select * from singup where email = ?"
    const search_query = mysql.format(sqlSearch, [email])
    await connection.query(search_query, async (err, result) => {
      connection.release()

      if (err) throw (err)
      if (result.length == 0) {
        console.log("--------> User does not exist")
        res.status(404)
        res.json("User does not exists")
      }
      else {
        const hashedPassword = result[0].password

        if (await bcrypt.compare(password, hashedPassword)) {
          console.log("---------> Login Successful")
          const token = generateAccessToken({ email: email })
          res.json({ accessToken: token })
        }
        else {
          console.log("---------> Password Incorrect")
          res.json("Invalid user or password, try again!")
        }
      }
    })
  })
})


app.listen(PORT, () => console.log(`Server Started on port ${PORT}...`))