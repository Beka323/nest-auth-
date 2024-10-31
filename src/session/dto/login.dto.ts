import { IsNotEmpty, IsString, IsEmail, Length } from "class-validator";

export class LoginDto {
    @IsString()
    @IsNotEmpty()
    username: string;
    @IsString()
    @IsNotEmpty()
    @Length(5, 25)
    password: string;
}
