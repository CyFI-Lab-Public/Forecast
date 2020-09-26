import json
import os
from pathlib import Path

from angr import Project

from simprocedures.models.function_model import FunctionModel, Parameter
from simprocedures.models.procedure_model import ProcedureModel


class ModelHandler:
    def __init__(self, models_path: str):
        self._model_data = {}
        if "~/" in models_path:
            models_path = os.path.join(os.path.expanduser('~'), models_path[2::])
        for f in Path(models_path).rglob('*.json'):
            with f.open() as lib:
                lib_data = json.load(lib)
                for func in lib_data:
                    self._model_data[func["name"]] = func

    def _model_from_json(self, json_entry: dict) -> FunctionModel:
        """
        Create function model from json entry
        """
        name = json_entry["name"]
        params = []
        for i in range(len(json_entry["parameters"])):
            param_name = json_entry["parameters"][i]
            param_type = None
            if "param_types" in json_entry:
                param_type = json_entry["param_types"][i]
            param_meta = None
            if "param_meta" in json_entry:
                param_meta = json_entry["param_meta"][i]
            param = Parameter(param_name, param_type, param_meta)
            params.append(param)
        cc = None
        if "calling_convention" in json_entry:
            cc = json_entry["calling_convention"]
        return FunctionModel(name, params, cc)

    def _get_model(self, name: str) -> FunctionModel:
        """
        Search for model in cached json data
        """
        if name in self._model_data:
            func_data = self._model_data[name]
            return self._model_from_json(func_data)
        raise ValueError(f"No model found for {name}")

    def create_procedure(self, name: str, proj: Project) -> ProcedureModel:
        """
        Creates a SimProcedure for the specified function
        """
        func_model = self._get_model(name)
        return ProcedureModel(proj, func_model)
