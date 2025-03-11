import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import routes from './routes/auth.routes.js';

const app = express();

//Middleware Globales
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());

//Rutas
app.get('/', (req, res, next) => {
    res.send("Welcome to API Login");
})

app.use('/api', routes)


export default app;