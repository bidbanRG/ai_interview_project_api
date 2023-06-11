
import express, { NextFunction, Request, Response } from "express";
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt, { VerifyErrors } from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());
// app.use('/',function(req, res, next) { //allow cross origin requests

   
    
//     res.setHeader('Access-Control-Allow-Origin', `http://localhost:5173/${req.baseUrl}`);

//     // Request methods you wish to allow
//     res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

//     // Request headers you wish to allow
//     res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

//     // Set to true if you need the website to include cookies in the requests sent
//     // to the API (e.g. in case you use sessions)
//    // res.setHeader('Access-Control-Allow-Credentials', true);
//     next();
// });



app.get('/',(req,res) => {
   res.send('Hello Deploy Succesfull');
})


type RequestBody = {
   fullname:string;
   password:string;
   email:string;
} 

type RequestError<T> = {
  err:T;
}

type Tokens = {
   accessToken:string;
   refreshToken:string;
}


const VerifyRefreshToken = (req:Request<unknown,unknown,RequestBody>,
                      res:Response<RequestError<'No Cookie Found' | "missing some payload" | VerifyErrors>>,next:NextFunction) => {
       

        const cookies = req.cookies;  
        if(!cookies?.jwt_refresh) return res.json({err:'No Cookie Found'});
        
       jwt.verify(cookies.jwt_refresh as string,process.env.REFRESH_TOKEN_SECRET as string, (err,decode) => {
             
             if(err) return res.status(401).json({err});
             
             const { fullname, password, email } = decode as RequestBody;
            
            if(!fullname || !password || !email) 
               return res.status(401).json({err:'missing some payload'});
           
            req.body = {fullname,password,email};
       })

       next();
      
}


app.post('/signup',(req:Request<any,Pick<Tokens,'accessToken'> | RequestError<'missing some payload'>,RequestBody>,res) => {

     
   const f = req.body;     

  if(!f.fullname || !f.password || !f.email) return res.status(400).json({err:'missing some payload'});
    
    
      
       const accessToken = jwt.sign(
       f,
       process.env.ACCESS_TOKEN_SECRET as string,
       {expiresIn:'45s'})
      
       const refreshToken = jwt.sign(
       f,
       process.env.REFRESH_TOKEN_SECRET as string,
       {expiresIn:'30d'})
     
       res.cookie('jwt',refreshToken,{
         httpOnly:true,
         secure:true,
         maxAge:1000 * 60 * 60 * 24 * 30,

      })
      
      res.cookie('jwt_access',accessToken,{
         maxAge:1000 * 45,
         secure:true
      })

      return res.status(200).json({accessToken});

})

// app.post('/login',(req:Request<any,RequestBody | RequestError<VerifyErrors>,Pick<Tokens,'accessToken'>>,res) => {

     
     
      
//        // const accessToken = jwt.ve(
//        // {'name':f?.name},
//        // process.env.ACCESS_TOKEN_SECRET as string,
//        // {expiresIn:'30s'})
        
//    console.log(req.cookies.jwt);
//        jwt.verify(req.body.accessToken,process.env.ACCESS_TOKEN_SECRET as string,(err,decode) => {
             
//              if(err) return res.status(401).json({err});

             
//             return res.status(200).json(decode as RequestBody);

//        })
      
      
     
      

      

// })

app.get('/token',VerifyRefreshToken,(req:Request<any,Pick<Tokens,'accessToken'>,any>,res:Response) => {

     
     
      

        const accessToken = jwt.sign(
       req.body,
       process.env.ACCESS_TOKEN_SECRET as string,
       {expiresIn:'30s'})
      
     res.json({accessToken});
      

      

})

app.listen(5000,() => {
   console.log('listening at PORT 3000');
})

export default app;