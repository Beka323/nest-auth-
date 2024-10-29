import { IsNotEmpty, IsString, IsEmail, Length } from "class-validator";

export class CreateUserDto {
    @IsString()
    @IsNotEmpty()
    username: string;
    @IsString()
    @IsNotEmpty()
    @IsEmail()
    email: string;
    @IsString()
    @IsNotEmpty()
    @Length(5, 30)
    password: string;
}
