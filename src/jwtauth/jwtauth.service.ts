import {
    Injectable,
    ConflictException,
    NotFoundException,
    BadRequestException,
    UnauthorizedException
} from "@nestjs/common";
import { JwtUser, JwtSchema } from "./schema/jwtauth.schema";
import { Model } from "mongoose";
import { InjectModel } from "@nestjs/mongoose";
import { CreateUserDto } from "./dto/user.dto";
import * as bcrypt from "bcryptjs";
import { LoginUserDto } from "./dto/login.dto";
import { JwtService } from "@nestjs/jwt";
import { Response, Request } from "express";
import { UpdateUserDto } from "./dto/update.dto";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class JwtauthService {
    constructor(
        @InjectModel(JwtUser.name) private jwtModel: Model<JwtUser>,
        private jwtService: JwtService,
        private configService: ConfigService
    ) {}
    // register user
    async registerUser(
        user: CreateUserDto
    ): Promise<{ msg: string; status: boolean }> {
        const findUserByEmail = await this.jwtModel.findOne({
            email: user.email
        });
        const findUserByUserName = await this.jwtModel.findOne({
            username: user.username
        });
        if (findUserByEmail || findUserByUserName) {
            throw new ConflictException("user already exisit");
        }
        const salt = await bcrypt.genSalt(10);
        const hashPwd = await bcrypt.hash(user.password, salt);
        const newUser = {
            username: user.username,
            email: user.email,
            password: hashPwd
        };
        const createUser = new this.jwtModel(newUser);
        createUser.save();
        return { msg: "user created", status: true };
    }
    // Login user check if the user is exsist and check if the password match the generate a access and refresh tokens
    async login(
        user: LoginUserDto,
        response: Response
    ): Promise<{ accessToken: string }> {
        const findUserByUserName = await this.jwtModel.findOne({
            username: user.username
        });
        if (!findUserByUserName) {
            throw new NotFoundException("user not found");
        }
        const match = await bcrypt.compare(
            user.password,
            findUserByUserName.password
        );
        if (!match) {
            throw new BadRequestException("incorrect password");
        }
        const payload = {
            id: findUserByUserName._id
        };
        const accessToken = await this.jwtService.signAsync(payload, {
            expiresIn: "15m"
        });
        const refreshToken = await this.jwtService.signAsync(payload, {
            expiresIn: "7d"
        });
        const currentTime = new Date();

        findUserByUserName.refreshtoken = refreshToken;
        findUserByUserName.lastlogin = currentTime;
        findUserByUserName.save();
        response.cookie("refreshtoken", refreshToken);
        return { accessToken };
    }
    // Get the user Info
    async getUser(id: string): Promise<any> {
        const findUser = await this.jwtModel.findById(id);
        if (!findUser) {
            throw new NotFoundException("no user found");
        }
        findUser.password = "";
        findUser.refreshtoken = "";
        return findUser;
    }
    //,Update user info
    async updateUser(
        id: string,
        updateUser: UpdateUserDto
    ): Promise<{ msg: string; status: boolean }> {
        const update = await this.jwtModel.findByIdAndUpdate(id, updateUser);
        if (!update) {
            throw new NotFoundException("no user  found");
        }

        update.save();
        return { msg: "updated", status: true };
    }
    // if the access token expired the client send a req to this endponit the end ponit extract the cookie and check if the token is valid if it valid send a new access token and refresh the refresh token
    async refreshToken(req: Request, res: Response): Promise<any> {
        const cookie = req.cookies.refreshtoken;
        const JWT_SECRET = this.configService.get<string>("SECRET");
        if (!cookie) {
            throw new UnauthorizedException("un authorized user");
        }

        try {
            const verifyToken = await this.jwtService.verifyAsync(cookie, {
                secret: JWT_SECRET
            });

            const accessToken = await this.jwtService.signAsync(
                { id: verifyToken.id },
                { secret: JWT_SECRET }
            );
            const refreshToken = await this.jwtService.signAsync(
                { id: verifyToken.id },
                { secret: JWT_SECRET }
            );
            res.cookie("refreshtoken", refreshToken);
            return { accessToken };
        } catch {
            throw new BadRequestException("the refreshToken is expired ");
        }
    }
    // Logout that clear the cookie and and it remove the value of refresh token from the database
    async logOut(req, res: Response): Promise<{ msg: string }> {
        const user = await this.jwtModel.findById(req.user.id);
        console.log(req.cookies);
        user.refreshtoken = "";
        user.save();
        res.clearCookie("refreshtoken");
        return { msg: "logged out" };
    }
}
