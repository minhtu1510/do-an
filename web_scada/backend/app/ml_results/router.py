"""ML results endpoints — reads train_ml.py output from disk. No numbers are
fabricated: everything 404s/501s explicitly until the real files exist."""

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, JSONResponse

from ..auth import require_role
from .service import ml_results_service

ml_results_router = APIRouter()


@ml_results_router.get("/status")
async def ml_status(_user=Depends(require_role("operator"))):
    return {
        "configured": ml_results_service.configured(),
        "results_dir": str(ml_results_service.results_dir),
        "experiments": ml_results_service.experiments(),
    }


@ml_results_router.get("/summary")
async def ml_summary(_user=Depends(require_role("operator"))):
    rows = ml_results_service.summary()
    if rows is None:
        return JSONResponse(
            status_code=501,
            content={
                "error": "ml_results_unavailable",
                "message": "summary_mean_std.csv not found — run train_ml.py --output-dir <dir> "
                           "then point ML_RESULTS_DIR at it (or copy the output into ml_results/).",
                "results_dir": str(ml_results_service.results_dir),
            },
        )
    return {"rows": rows}


@ml_results_router.get("/experiments/{experiment}/runs")
async def ml_runs(experiment: str, _user=Depends(require_role("operator"))):
    return {"experiment": experiment, "runs": ml_results_service.list_runs(experiment)}


@ml_results_router.get("/experiments/{experiment}/runs/{run}/confusion-matrix")
async def ml_confusion_matrix(experiment: str, run: str, _user=Depends(require_role("operator"))):
    data = ml_results_service.confusion_matrix(experiment, run)
    if data is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "experiment": experiment, "run": run},
        )
    return {"experiment": experiment, "run": run, **data}


@ml_results_router.get("/experiments/{experiment}/runs/{run}/feature-importance")
async def ml_feature_importance(experiment: str, run: str, _user=Depends(require_role("operator"))):
    data = ml_results_service.feature_importance(experiment, run)
    if data is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "experiment": experiment, "run": run},
        )
    return {"experiment": experiment, "run": run, "features": data}


@ml_results_router.get("/experiments/{experiment}/runs/{run}/pr-curve.png")
async def ml_pr_curve(experiment: str, run: str, _user=Depends(require_role("operator"))):
    path = ml_results_service.pr_curve_path(experiment, run)
    if path is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "experiment": experiment, "run": run},
        )
    return FileResponse(path, media_type="image/png")
