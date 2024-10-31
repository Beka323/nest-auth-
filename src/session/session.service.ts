import {
    Injectable,
    ConflictException,
    NotFoundException,
    BadRequestException,
    UnauthorizedException
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import * as bcrypt from "bcryptjs";
import { SessionUser } from "./schema/session.schema";
import { SessionUserDto } from "./dto/session.dto";
import { LoginDto } from "./dto/login.dto";
import { Request, Response } from "express";
import { UpdateUserDto } from "./dto/update.dto";
@Injectable()
export class SessionService {
    constructor(
        @InjectModel(SessionUser.name) private sessionModel: Model<SessionUser>
    ) {}
    // Get user
    async getUser(req: Request, id: string): Promise<any> {
        if (!req.session["userId"]) {
            throw new UnauthorizedException("Un authorized User");
        }
        const findUser = await this.sessionModel.findById(
            req.session["userId"]
        );
        findUser.password = "";
        return findUser;
    }
    //,Register
    async register(
        user: SessionUserDto
    ): Promise<{ msg: string; status: boolean }> {
        const findUser = await this.sessionModel.findOne({ email: user.email });
        if (findUser) {
            throw new ConflictException("user already exist");
        }
        const genSalt = await bcrypt.genSalt(10);
        const hashPwd = await bcrypt.hash(user.password, genSalt);

        const newUser = {
            username: user.username,
            email: user.email,
            password: hashPwd
        };
        const createUser = new this.sessionModel(newUser);
        createUser.save();
        return { msg: "user created", status: true };
    }
    // Login
    async login(
        user: LoginDto,
        req: Request,
        res: Response
    ): Promise<{ msg: string; status: boolean }> {
        const findUser = await this.sessionModel.findOne({
            username: user.username
        });
        if (!findUser) {
            throw new NotFoundException("user not found");
        }
        const match = await bcrypt.compare(user.password, findUser.password);
        if (!match) {
            throw new BadRequestException("Incorrect password");
        }
        const date = new Date();
        findUser.lastlogin = date;
        findUser.save();
        req.session["userId"] = findUser._id.toString();
        return { msg: "logged in", status: true };
    }
    // Update user
    async updateUser(
        id: string,
        updateUser: UpdateUserDto,
        req
    ): Promise<{ msg: string; status: boolean }> {
        if (!req.session.userId) {
            throw new UnauthorizedException("un autorized user");
        }
        const findAndUpdate = await this.sessionModel.findByIdAndUpdate(
            id,
            updateUser
        );
        if (!findAndUpdate) {
            throw new NotFoundException("no user found");
        }
        await findAndUpdate.save();
        return { msg: "updated", status: true };
    }
    // Log Out
    async logOut(req): Promise<{ msg: string; status: boolean }> {
        if (!req.session.userId) {
            throw new UnauthorizedException("un authorized user");
        }
        req.session.destroy();
        return { msg: "logoutppp", status: true };
    }
}
