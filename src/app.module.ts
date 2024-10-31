import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { MongooseModule } from "@nestjs/mongoose";
import { JwtauthModule } from './jwtauth/jwtauth.module';
import { SessionModule } from './session/session.module';
@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true
        }),
        MongooseModule.forRoot(process.env.DATABASE_URL),
        JwtauthModule,
        SessionModule
    ],
    controllers: [],
    providers: []
})
export class AppModule {}
