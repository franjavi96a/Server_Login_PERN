import app from './app.js';
import config from './config.js';

const main = () => {
    app.listen(config.port, () => {
        console.log(`Server running on port ${config.port}`);
    })
}

main();
