import { Module } from "@nestjs/common";
import { SessionController } from "./session.controller";
import { SessionService } from "./session.service";
import { MongooseModule } from "@nestjs/mongoose";

import { SessionUser, SessionSchema } from "./schema/session.schema";

@Module({
    imports: [
        MongooseModule.forFeature([
            { name: SessionUser.name, schema: SessionSchema }
        ])
    ],
    controllers: [SessionController],
    providers: [SessionService]
})
export class SessionModule {}
