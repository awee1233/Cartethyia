// @ts-check
import { module } from "@prisma/composer";
import cartethyiaService from "./service.mjs";

export default module("sodarouutue", ({ provision }) => {
  provision(cartethyiaService);
});
