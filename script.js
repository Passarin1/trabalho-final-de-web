function mostrarDicas() {
    const tipoPele = document.getElementById("tipo-pele").value;
    const dicasDiv = document.getElementById("dicas-personalizadas");

    let dicas;
    
    switch (tipoPele) {
        case "oleosa":
            dicas = "<p>Para pele oleosa, use produtos em gel e evite cremes muito pesados. Procure por ingredientes como ácido salicílico.</p>";
            break;
        case "seca":
            dicas = "<p>Para pele seca, escolha hidratantes mais densos e com ingredientes como ácido hialurônico e glicerina.</p>";
            break;
        case "normal":
            dicas = "<p>Pele normal se beneficia de uma rotina equilibrada. Use hidratantes leves e protetores solares diários.</p>";
            break;
        case "mista":
            dicas = "<p>Para pele mista, use produtos diferentes em áreas diferentes, como cremes mais leves na zona T e mais ricos nas bochechas.</p>";
            break;
        default:
            dicas = "<p>Selecione um tipo de pele para ver dicas personalizadas.</p>";
            break;
    }

    dicasDiv.innerHTML = dicas;
}
