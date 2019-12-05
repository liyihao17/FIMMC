from sklearn.manifold import TSNE
from sklearn.cluster import k_means
from pandas.core.frame import DataFrame
import numpy as np
import ImportMessage
import FrequentItemMining
import FeatureBuild

a = ImportMessage.import_file('S7_1.pcap')
b = ImportMessage.import_file('http5.pcap')
c = a + b
text_type, mixed_type, bin_type = ImportMessage.MessageClassifier(c)
print('Messages are classified.')
print('text type:',len(text_type),' bin type:',len(bin_type),' mixed type',len(mixed_type))
close_ngram = FrequentItemMining.get_close_ngram(text_type,'text',3,7,3,0.2)
print('Close n-gram pieces are obtained.')
feature_matrix = FeatureBuild.build_matrix(text_type,close_ngram)
print('Feature Matrix is built.')

data_l = DataFrame(feature_matrix)
dataMat = np.array(data_l)

pca_tsne = TSNE(n_components=2)
newMat = pca_tsne.fit_transform(dataMat)
data_l = DataFrame(newMat)
data_l = np.array(data_l)
data_l = data_l.tolist()
print(data_l)

clf = k_means(data_l,6)
classification = clf[1]
print(classification)
num = max(classification)
result = []
for i in range(num+1):
    tmp = []
    for j in range(len(classification)):
        if classification[j] == i:
            tmp.append(text_type[j])
    result.append(tmp)

for i in range(len(result)):
    for j in range(len(result[i])):
        print(result[i][j])
    print()
    print()