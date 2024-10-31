import { PartialType } from "@nestjs/mapped-types";
import { SessionUserDto } from "./session.dto";

export class UpdateUserDto extends PartialType(SessionUserDto) {}
