const express = require('express');
const app = express();
const port = 8080;

app.listen(port, function(err){
    if(err){
        console.log(`Error in running server : ${err}`);
        return;
    }
    console.log(`Successfully running on port : ${port}`)
})