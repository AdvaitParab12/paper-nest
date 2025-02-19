const express=require("express");

const app=express()
app.set("view engine","ejs")
app.use(express.static("public")) //static files

app.get("/",(req,res)=>{
    res.render("homepage",{title:"AcademiaPress"})

})

app.listen(3000,()=>{
    console.log("server fired up")
})