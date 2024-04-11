import os

def lister_extensions_et_nombres(repertoire):
    extensions = {}  # Utilisation d'un dictionnaire pour stocker les extensions et leurs nombres correspondants

    # Parcourir récursivement l'arborescence
    for dossier_racine, sous_repertoires, fichiers in os.walk(repertoire):
        for fichier in fichiers:
            # Obtenir l'extension du fichier
            _, extension = os.path.splitext(fichier)
            # Normaliser l'extension en minuscules
            extension = extension.lower()
            # Ajouter l'extension au dictionnaire et incrémenter le compteur de fichiers correspondant
            extensions[extension] = extensions.get(extension, 0) + 1

    return extensions

# Exemple d'utilisation
repertoire = "N:\Référence_images_déjà_sélectionnées"  # Remplacez cela par le chemin du répertoire à parcourir

extensions_et_nombres = lister_extensions_et_nombres(repertoire)
print("Nombre de fichiers par extension :")
for extension, nombre in extensions_et_nombres.items():
    print(f"{extension} : {nombre}")
