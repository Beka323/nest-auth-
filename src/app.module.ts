import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { MongooseModule } from "@nestjs/mongoose";
import { JwtauthModule } from './jwtauth/jwtauth.module';
@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true
        }),
        MongooseModule.forRoot(process.env.DATABASE_URL),
        JwtauthModule
    ],
    controllers: [],
    providers: []
})
export class AppModule {}
