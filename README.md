
## Overview
This repository provides the python implementation for our paper 'Flow timeout matters: Investigating the impact of active and idle timeouts on the performance of machine learning models in detecting security threats'


## Table of Contents

- [Introduction](#introduction)
- [Datasets](#datasets)
- [Feature extraction](#feature-extraction)
- [Data labeling](#data-labeling)
- [Implementation details](#implementation-details)
- [Distributed learning in a multiple timeouts environment](#distributed-learning-in-a-multiple-timeouts-environment)
- [Visualization and Results](#visualization-and-results)
- [Usage](#usage)
- [License](#license)

## Introduction
In the era of high-speed networks and massive data, several network security technologies are shifting focus from payload-based to flow-based methods. This has led to the incorporation of Machine Learning (ML) models in network security systems, where high-quality network flow features are of paramount importance. However, limited attention has been dedicated to studying the impact of the flow metering hyperparameters, specifically idle and active timeouts, on ML models’ performance. Our paper, therefore aims to address this gap by designing a series of experiments related to flow features and learning models in the case of Network Intrusion Detection Systems (NIDS) (Figure 1). Our experiments investigate the impact idle and active timeouts have on the quality of the extracted features from network data and their subsequent impact on the performance of ML models. 



**<p align="center">Figure 1: The overflow of the proposed design of experiments.</p>**
<p align="center">
<img src="https://github.com/meryemJanatiIdrissi/Flow-timeout-matters/blob/main/Figures/flow-overflow.jpg" />
</p>


## Datasets
The datasets used in this project are [USTC-TFC2016](https://github.com/yungshenglu/USTC-TFC2016), [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset), and [CUPID](https://www.cupid.directory/).  For each dataset, we utilized the publicly available PCAP files. Below, we outline the necessary steps for feature extraction and labeling processes. Detailed instructions and scripts are provided to help replicate these steps and ensure consistent feature generation and labeling across datasets.

## Feature extraction
For this project, we used three flow exporters, NFStream, Zeek (Bro), and Argus, to extract network features from each dataset.

- **NFStream:** We provide custom plugins developed by our team for specialized feature extraction. Additionally, a Jupyter notebook is included as an example, demonstrating feature extraction with various timeout settings (`feature_extraction/NFStream/nfstream_extractor`).
> 

- **Zeek:** Bash scripts are available for each dataset, automating feature extraction using Zeek (`feature_extraction/Zeek`).
- **Argus:** Similarly, Argus-specific bash scripts are included to extract flow features with different timeouts' values (`feature_extraction/Argus`).



## Data labeling
For each dataset and for each flow exporter, we have included a notebook with the specific steps used to data labeling process after feature extraction (in `labeling_datasets_timeouts`).

+ The **USTC-TFC2016** dataset was straightforward to label, as it includes separate PCAP files for benign and malware traffic. 

+ For **CIC-IDS2017** and **UNSW-NB15** datasets, we labeled the extracted data by mapping each flow with the publicly available ground truth using the five-tuple: `['source IP address', 'source port', 'destination IP address', 'destination port', 'transport protocol']`. 

+ For the CUPID dataset, we implemented the labeling rules as specified on the dataset’s official website to accurately label the flows.


## Implementation details 

#### Timeouts
NFStream (32 combinations): 
- The idle timeout (min) takes values from [0.5, 1, 2, 3, 4, 5, 6, 10].
- The active timeout (min) varies within the list [2, 3, 4, 5, 30, 60].

Zeek and Argus:
- The idle timeout (min) takes values from [0.5, 1, 2, 3, 4, 5, 6, 10, 30, 60]

#### FLow exporters
- [NFStream](https://www.nfstream.org/)
- [Zeek (Bro)](https://zeek.org/)
- [Argus](https://openargus.org/documentation)

#### Machine learning algorithms
- Extra trees classifier(ET)
- Random forest (RF)
- Multi-Layer Perceptron (MLP)

#### Feature selection Model
- Extra trees (ET)


For each flow exporter, dataset, and ML model, we provide a dedicated notebook located in `evaluation/<flow exporter>/<dataset>/notebooks`. These notebooks contain comprehensive workflows for training and testing, ensuring reproducibility.

#### Training data size vs model performance
We examine the impact of varying amounts of training data on the performance of the ETC model and identify representative data for the best timeout. For each dataset, we consider the best timeout on the NFStream baseline feature set, and we incrementally increase the size of the training data while maintaining the test set constant (see `evaluation/<flow exporter>/<dataset>/cumulativeLearning`).


#### Explainability
In this project, the SHAP (SHapley Additive exPlanations) approach was utilized to interpret the predictions made by the ETC model on the NFStream feature set for
both datasets USTC-TFC2016 and CICIDS2017 (`explainability/notebooks`). 




## Distributed learning in a multiple timeouts environment
We model a realistic scenario involving distributed NIDS instances, each owning data extracted using distinct idle and active timeouts. For this purpose, we propose the use of federated learning as illustrated in Figure 2.

**<p align="center">Figure 2: Distribued scheme using federated learning.</p>**
<p align="center">
<img src="https://github.com/meryemJanatiIdrissi/Flow-timeout-matters/blob/main/Figures/FL_scheme.jpg?raw=true" alt="Distribued scheme using federated learning" width="500">
</p>

For each dataset, we train the MLP model on features extracted using NFStream (see `federated_learning/notebooks`). 






## Visualization and Results
- The figures for explainability are saved in `explainability/figures/<dataset>`.
- The plots are saved in `plots`.
- The results are saved in `evaluation/<flow exporter>/<dataset>/results`.
- The checkpoints are saved in `evaluation/<flow exporter>/<dataset>/Checkpoints`.


## Usage
To use the project, follow these steps:

1. Clone the repository to your local machine.
2. Install the required dependencies mentioned in the `requirements.txt` file.
3. Run the provided Python scripts or Jupyter notebooks to process data of train/evaluate the machine learning models.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

© 2024 Meryem Janati Idrissi