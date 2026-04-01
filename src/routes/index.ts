import { Router, type IRouter } from "express";
import healthRouter from "./health";
import intelRouter from "./intel";
import feedRouter from "./feed";
import searchRouter from "./search";
import feedbackRouter from "./feedback";
import appsRouter from "./apps";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/intel", intelRouter);
router.use("/intel", feedRouter);
router.use("/intel", searchRouter);
router.use("/feedback", feedbackRouter);
router.use("/apps", appsRouter);

export default router;
