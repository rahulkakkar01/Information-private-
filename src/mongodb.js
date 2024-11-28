const mongoose = require( mongoose)

mongoose.connect("mongodb://localhost:27017/information")
.then(()=>{
    console.log("mongodb connected")
})
.catch(()=>{
    console.log=("failed to connected")
})

const loginSchema=new mongoose.loginSchema({
    name:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    }

})

const collection=new mongoose.model("collection1",loginSchema)

module.exports=collection