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

// Manejo de errores globales
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.use('/api', routes)


export default app;