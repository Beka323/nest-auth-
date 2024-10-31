import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import * as cookieParser from "cookie-parser";
import * as session from "express-session";
import helmet from "helmet";
import * as MongoDbStore from "connect-mongodb-session";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.use(helmet());
    app.use(cookieParser());
    const mongoStore = MongoDbStore(session);
    const store = new mongoStore({
        uri: process.env.DATABASE_URL,
        collection: "sessions"
    });
    app.use(
        session({
            cookie: {
                maxAge: 1000 * 60 * 60,
                httpOnly: true
            },
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            store: store
        })
    );
    await app.listen(3000);
}
bootstrap();
