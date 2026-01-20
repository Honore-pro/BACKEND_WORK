const mysql=require("mysql2")

const database=mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"",
    database:"users",
})


database.connect((err)=>{
    if(err)throw err
    console.log('database is connected successfully')
})

module.exports=database;