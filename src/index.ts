
import express, { NextFunction, Request, Response } from "express";
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt, { VerifyErrors } from 'jsonwebtoken';
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const session = require('express-session');
dotenv.config();
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  // Set the allowed origin(s)
  res.setHeader('Access-Control-Allow-Origin', process.env.CLIENT_URL + `${req.baseUrl}`);

  // Allow the credentials to be sent
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Set the allowed methods
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');

  // Set the allowed headers
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  next();
});
app.use(session({
   secret:'23432eedsfdsf',
   resave:false,
   saveUninitialized:true,
   cookie:{
      secure:true,
      maxAge:1000 * 60 * 60 * 24
  },
}))
app.use(cookieParser());
app.use(cors({
   origin:process.env.CLIENT_URL,
  }));
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_ID,
      callbackURL: '/auth/google/callback',
    },
    (accessToken:any, refreshToken:any, profile:any, done:any) => {
      // This callback function is called after successful authentication
      // You can perform any necessary user data handling here
      // For example, create a new user in your database or retrieve an existing user
      // Then call the done() function to proceed with the authentication process
      done(null, profile);
    }
  )
);
app.use(passport.initialize());
app.use(passport.session());


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




app.get('/',(req,res) => {
   res.send('Hello Deploy Succesfull');
})

passport.serializeUser((user:any, done:any) => {
  done(null, user);
});
passport.deserializeUser((user:any, done:any) => {
  // Find the user by ID in your database or data source
    
    done(null, user);

});
// Routes
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile',"email"] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', 
   { failureRedirect: '/login/failed',
      
  }),(req,res) => {
     if(req.user){
        
      const refreshToken = jwt.sign(
       req.user,
       process.env.REFRESH_TOKEN_SECRET as string,
       {expiresIn:'1d'})
       
       

       res.cookie('jwt',refreshToken,{
         httpOnly:true,
         maxAge:1000 * 60 * 60 * 24,
         secure:true,
      })
       return res.redirect(301,process.env.CLIENT_URL + '/interview');
    }
  }
);







const VerifyRefreshToken = (req:Request<unknown,unknown,RequestBody>,
                      res:Response<RequestError<'No Cookie Found' | "missing some payload" | VerifyErrors>>,next:NextFunction) => {
       

        const cookies = req.cookies;  
        if(!cookies?.jwt) return res.json({err:'No Cookie Found'});
        
       jwt.verify(cookies.jwt as string,process.env.REFRESH_TOKEN_SECRET as string, (err,decode) => {
             
             if(err) return res.status(401).json({err});
             
             const { fullname, password, email } = decode as RequestBody;
            
            if(!fullname || !password || !email) 
               return res.status(401).json({err:'missing some payload'});
           
            req.body = {fullname,password,email};
       })

       next();
      
}




app.get('/login/success',(req,res)=>{
    
    const cookies = req.cookies; 
     
        if(!cookies?.jwt)  
            {   
               
                
                return res.status(401).json({err:"No Cookie Found"});
            }
       else{ 
       jwt.verify(cookies.jwt as string,process.env.REFRESH_TOKEN_SECRET as string, (err,decode) => {
             
             if(err) {
               
                return res.status(401).json({err});
            }else{
             
              return res.status(200).json({
                  success:true,
                 user:decode,
             })
          }
       })
     }
})



app.get('/login/failed',(req,res)=>{
    
    res.send('Login Failed');
})



app.post('/signup',(req:Request<any,"Succesfull"| RequestError<'missing some payload'>,RequestBody>,res) => {

     
   const f = req.body;     

  if(!f.fullname || !f.password || !f.email) return res.status(400).json({err:'missing some payload'});
    
    
      
     
      
       const refreshToken = jwt.sign(
       f,
       process.env.REFRESH_TOKEN_SECRET as string,
       {expiresIn:'30d'})
       

       res.cookie('jwt',refreshToken,{
         httpOnly:true,
         maxAge:1000 * 60 * 60 * 24 * 30,
         secure:true,
      })
      
      

      return res.send('Succesfull');

})



app.get('/token',VerifyRefreshToken,(req:Request<any,Pick<Tokens,'accessToken'>,any>,res:Response) => {

     
     
      

        const accessToken = jwt.sign(
       req.body,
       process.env.ACCESS_TOKEN_SECRET as string,
       {expiresIn:'30s'})
      
     res.json({accessToken});
      

      

})
app.get('/clear',(_,res)=>{
    
    res.clearCookie('jwt');
    res.status(201).send('you cookie cleared');
})

app.listen(5000,() => {
   console.log('listening at PORT 3000',process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET_ID);
})

export default app;