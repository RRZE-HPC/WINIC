import numpy as np
import yaml


def read_WINIC_db(path: str):
    with open(path, "r") as file:
        raw_content = file.read()
    return yaml.safe_load(raw_content)["instructions"]


def calculate_deviation():
    for runs in [3, 4, 5]:
        vals = {}
        for i in [0, 1, 2, 3, 4]:
            dbName = f"runs{runs}_{i}.yaml"
            db = read_WINIC_db("dev/runs_impact/" + dbName)

            for instruction in db:
                # print(instruction)
                for lat in instruction["operandLatencies"]:
                    # create standard name for a metric
                    stdNameMin = instruction["llvmName"] + lat["sourceOperand"] + lat["targetOperand"] + "min"
                    stdNameMax = instruction["llvmName"] + lat["sourceOperand"] + lat["targetOperand"] + "max"
                    if stdNameMin not in vals.keys():
                        vals[stdNameMin] = np.repeat(np.nan, 5)
                    if stdNameMax not in vals.keys():
                        vals[stdNameMax] = np.repeat(np.nan, 5)
                    if lat["latencyMin"] is not None:
                        vals[stdNameMin][i] = float(lat["latencyMin"])
                    if lat["latencyMax"] is not None:
                        vals[stdNameMax][i] = float(lat["latencyMax"])

        valArray = np.array([v for v in vals.values()])
        valArray = valArray[~np.all(np.isnan(valArray), axis=1)]
        deviations = np.nanstd(valArray, axis=1, ddof=1)

        # penetalize nan values
        penalty = np.nanmax(deviations)
        nanFractions = np.mean(np.isnan(valArray), axis=1)
        penalties = nanFractions * penalty
        # print(f"{penalty=}")
        correctedDeviations = deviations + penalties
        
        meanDev = np.nanmean(correctedDeviations)
        print(f"for {runs} runs per kernel we get a std deviation score of {meanDev:.4f}")

if __name__ == "__main__":
    calculate_deviation()