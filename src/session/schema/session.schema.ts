import { Schema, SchemaFactory, Prop } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";

type schemaType = HydratedDocument<SessionUser>;

@Schema({
    timestamps: true
})
export class SessionUser {
    @Prop({ type: String })
    username: string;
    @Prop({ type: String, unique: true })
    email: string;
    @Prop({ type: String })
    password: string;
    @Prop({ type: String, enum: ["admin", "user", "editor"], default: "user" })
    role: string;
    @Prop({ type: Date, default: null })
    lastlogin: Date;
}

export const SessionSchema = SchemaFactory.createForClass(SessionUser);
