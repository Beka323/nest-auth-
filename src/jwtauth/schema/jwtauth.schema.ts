import { SchemaFactory, Schema, Prop } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";

type documentDb = HydratedDocument<JwtUser>;

@Schema({
    timestamps: true
})
export class JwtUser {
    @Prop({ type: String, unique: true })
    username: string;
    @Prop({ type: String })
    email: string;
    @Prop({ type: String })
    password: string;
    @Prop({ type: String, default: null })
    refreshtoken: string;
    @Prop({ type: String, default: null })
    lastlogin: Date;
}

export const JwtSchema = SchemaFactory.createForClass(JwtUser);
