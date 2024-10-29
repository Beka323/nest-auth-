import { Module } from "@nestjs/common";
import { JwtauthController } from "./jwtauth.controller";
import { JwtauthService } from "./jwtauth.service";
import { JwtUser, JwtSchema } from "./schema/jwtauth.schema";
import { MongooseModule } from "@nestjs/mongoose";
import { JwtModule } from "@nestjs/jwt";
import { ConfigModule, ConfigService } from "@nestjs/config";
@Module({
    imports: [
        ConfigModule,
        MongooseModule.forFeature([{ name: JwtUser.name, schema: JwtSchema }]),
        JwtModule.registerAsync({
            useFactory: (configService: ConfigService) => ({
                secret: configService.get<string>("JWT_SECRET")
            }),
            inject: [ConfigService]
        })
    ],
    controllers: [JwtauthController],
    providers: [JwtauthService]
})
export class JwtauthModule {}
