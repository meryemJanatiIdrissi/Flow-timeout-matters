import numpy as np
import math 

class Stats:
    """
    Stats Interface

    This interface defines methods for calculating various statistics.
    Subclasses should implement these methods to provide specific statistical calculations.

    Methods:
    - average(): Calculate the average of the data.
    - median(): Calculate the median of the data.
    - mode(): Calculate the mode of the data.
    - variance(): Calculate the variance of the data.
    - std_deviation(): Calculate the standard deviation of the data.
    - coeff_of_variation(): Calculate the coefficient of variation of the data.
    - skew_from_median(): Calculate the skewness of the data relative to the median.
    - skew_from_mode(): Calculate the skewness of the data relative to the mode.
    - min(): Get the minimum value in the data.
    - max(): Get the maximum value in the data.
    """
    def average(self):
        pass

    def median(self):
        pass

    def mode(self):
        pass 

    def variance(self):
        pass
    
    def std_deviation(self):
        pass

    def coeff_of_variation(self):
        pass

    def skew_from_median(self):
        pass

    def skew_from_mode(self):
        pass 
    
    def min(self):
        pass
    
    def max(self):
        pass


class StatsCollection(Stats): 
    """
    StatsCollection Class

    This class implements the Stats interface for a collection of statistical objects.

    Attributes:
    - inner_collection: The collection of statistical objects.

    Methods:
    - average(): Calculate the average of each statistical object in the collection.
    - median(): Calculate the median of each statistical object in the collection.
    - mode(): Calculate the mode of each statistical object in the collection.
    - variance(): Calculate the variance of each statistical object in the collection.
    - std_deviation(): Calculate the standard deviation of each statistical object in the collection.
    - coeff_of_variation(): Calculate the coefficient of variation of each statistical object in the collection.
    - skew_from_median(): Calculate the skewness of each statistical object in the collection relative to the median.
    - skew_from_mode(): Calculate the skewness of each statistical object in the collection relative to the mode.
    - min(): Get the minimum value among all statistical objects in the collection.
    - max(): Get the maximum value among all statistical objects in the collection.
    """
    def __init__(self, stats) -> None:
        self.inner_collection = stats

    def average(self):
        avgs = np.empty(len(self.inner_collection))
        for i, stats in enumerate(self.inner_collection):
            avgs[i] = stats.average()

        return avgs

    def median(self):
        pass

    def mode(self):
        pass 

    def variance(self):
        pass
    
    def std_deviation(self):
        pass

    def coeff_of_variation(self):
        pass

    def skew_from_median(self):
        pass

    def skew_from_mode(self):
        pass 
    
    def min(self) -> float:
        return np.min(self.values)
    
    def max(self) -> float:
        return np.max(self.values)

class WeightedIterableStats(Stats):
    """
    WeightedIterableStats Class

    This class provides statistical calculations for iterables with associated weights.

    Attributes:
    - values: The values to be used for calculations.
    - weights: The weights corresponding to each value.

    Methods:
    - average(): Calculate the weighted average of the values.
    - median(): Calculate the weighted median of the values.
    - mode(): Calculate the mode of the values (not implemented).
    - variance(): Calculate the weighted variance of the values.
    - std_deviation(): Calculate the weighted standard deviation of the values.
    - coeff_of_variation(): Calculate the coefficient of variation of the values.
    - skew_from_median(): Calculate the skewness of the values relative to the median.
    - skew_from_mode(): Calculate the skewness of the values relative to the mode.
    - min(): Get the value with the minimum weight.
    - max(): Get the value with the maximum weight.
    """
    def __init__(self, values, weights) -> None:
        self.values = values
        self.weights = weights

    def average(self) -> float:
        if np.sum(self.weights) == 0:
            return 0
        return np.average(self.values, weights=self.weights)
    
    def median(self) -> float:
        total_weight = np.sum(self.weights)
        half_total_weight = total_weight/2
        is_weight_even = (total_weight % 2) == 0
        accumulated_weight = 0
        for i, weight in enumerate(self.weights):
            accumulated_weight += weight
            if is_weight_even:
                if accumulated_weight == half_total_weight-0.5:
                    return (self.values[i-1] + self.values[i])/2
                elif accumulated_weight == half_total_weight+0.5:
                    return self.values[i]
            if accumulated_weight >= half_total_weight:
                return self.values[i]
            
        raise Exception('Logical error.')

    def mode(self) -> float:
        raise Exception('Not implemented') 

    def variance(self) -> float:
        if np.sum(self.weights) == 0:
            return 0
        return np.average((self.values-self.average())**2, weights=self.weights)
    
    def std_deviation(self) -> float:
        return math.sqrt(self.variance())

    def coeff_of_variation(self) -> float:
        if self.average() != 0:
            return self.std_deviation() / self.average()
        else:
            return 0

    def skew_from_median(self) -> float:
        #  Skew = 3 * (Mean – Median) / Standard Deviation
        if self.std_deviation() != 0:
            return 3 * (self.average() - self.median()) / self.std_deviation()
        else:
            return 0

    def skew_from_mode(self) -> float:
        #  Skew =  (Mean – Mode) / Standard Deviation
        if self.std_deviation() != 0:
            return (self.average() - self.mode()) / self.std_deviation()
        else:
            return 0
    
    def min(self):
        if np.sum(self.weights) == 0:
            return 0
        else:    
            return self.values[np.argmin(self.weights)]
    
    def max(self):
        if np.sum(self.weights) == 0:
            return 0
        else:
            return self.values[np.argmax(self.weights)]



class IterableStats(Stats):
    """
    IterableStats Class

    This class provides statistical calculations for iterables such as lists.

    Attributes:
    - values: The iterable containing the values for calculations.

    Methods:
    - average(): Calculate the average of the values.
    - median(): Calculate the median of the values.
    - mode(): Calculate the mode of the values (not implemented).
    - variance(): Calculate the variance of the values.
    - std_deviation(): Calculate the standard deviation of the values.
    - coeff_of_variation(): Calculate the coefficient of variation of the values.
    - skew_from_median(): Calculate the skewness of the values relative to the median.
    - skew_from_mode(): Calculate the skewness of the values relative to the mode.
    - min(): Get the minimum value in the values.
    - max(): Get the maximum value in the values.
    """
    def __init__(self, values) -> None:
        self.values = values

    def average(self) -> float:
        if len(self.values) != 0:
            return np.average(self.values)
        else:
            return None
    
    def median(self) -> float:
        if len(self.values) != 0:
            return np.median(self.values)
        else:
            return None

    def mode(self) -> float:
        raise Exception('Not implemented') 

    def variance(self) -> float:
        if len(self.values) >= 2:
            return np.var(self.values)
        else:
            return None
    
    def std_deviation(self) -> float:
        if len(self.values) >= 2:
            return np.std(self.values)
        else:
            return None
        

    def coeff_of_variation(self) -> float:
        avg = self.average()
        std = self.std_deviation()
        if avg not in {0, None} and std is not None:
            return std / avg
        else:
            return None

    def skew_from_median(self) -> float:
        #  Skew = 3 * (Mean – Median) / Standard Deviation
        std = self.std_deviation()
        if std not in {0, None}:
            return 3 * (self.average() - self.median()) / std
        else:
            return None

    def skew_from_mode(self) -> float:
        #  Skew =  (Mean – Mode) / Standard Deviation
        if self.std_deviation() not in {0, None}:
            return (self.average() - self.mode()) / self.std_deviation()
        else:
            return None
    
    def min(self):
        if len(self.values) != 0:
            return np.min(self.values)
        else:
            return None
    
    def max(self):
        if len(self.values) != 0:
            return np.max(self.values)
        else:
            return None

       