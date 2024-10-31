import {
    Controller,
    Get,
    Post,
    Patch,
    Body,
    Res,
    Req,
    ValidationPipe,
    Param
} from "@nestjs/common";
import { Request, Response } from "express";
import { SessionUserDto } from "./dto/session.dto";
import { UpdateUserDto } from "./dto/update.dto";

import { LoginDto } from "./dto/login.dto";

import { SessionService } from "./session.service";

@Controller("session")
export class SessionController {
    constructor(private sessionService: SessionService) {}
    // Get User
    @Get("user/:id")
    async getUser(@Req() req: Request, @Param() id: string): Promise<any> {
        return this.sessionService.getUser(req, id);
    }
    // Register User
    @Post("register")
    async register(
        @Body(ValidationPipe) user: SessionUserDto
    ): Promise<{ msg: string; status: boolean }> {
        return this.sessionService.register(user);
    }
    @Post("login")
    async login(
        @Body(ValidationPipe) user: LoginDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<{ msg: string; status: boolean }> {
        return this.sessionService.login(user, req, res);
    }
    @Patch("update/:id")
    async updateUser(
        @Param("id") id: string,
        @Body() updateUser: UpdateUserDto,
        @Req() req: Request
    ): Promise<{ msg: string; status: boolean }> {
        return this.sessionService.updateUser(id, updateUser, req);
    }
    @Get("logout")
    async logOut(
        @Req() req: Request
    ): Promise<{ msg: string; status: boolean }> {
        return this.sessionService.logOut(req);
    }
}
