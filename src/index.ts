
import express from "express";

const app = express();


app.get('/',(req,res) => {
   res.send('Hello Deploy Succesfull');
})


app.listen(3000,() => {
   console.log('listening at PORT 3000');
})

export default app;