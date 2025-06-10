<?php
include_once('config.php'); // Certifique-se de que 'config.php' configura a conexão $conexao

// Verifica se houve um envio de formulário via POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Recebe e sanitiza os dados do formulário
    $email = filter_var($_POST["email"], FILTER_SANITIZE_EMAIL);
    $senha_digitada = $_POST["senha"]; // A senha digitada pelo usuário

    // Validação básica: verifica se os campos não estão vazios
    if (empty($email) || empty($senha_digitada)) {
        echo "Por favor, preencha todos os campos.";
    } else {
        // Prepara a consulta SQL para buscar o usuário pelo email
        // **IMPORTANTE**: Não inclua a senha na consulta SELECT para verificação direta.
        // A senha deve ser verificada APÓS recuperá-la do banco de dados e usar password_verify().
        $stmt = $conexao->prepare("SELECT email, senha, tipo FROM clientes WHERE email = ?");
        $stmt->bind_param("s", $email); // 's' indica que o parâmetro é uma string

        if ($stmt->execute()) {
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $senha_hash_armazenada = $row['senha']; // A senha com hash armazenada no banco de dados
                $tipo_usuario = $row['tipo']; // O tipo de usuário armazenado no banco de dados

                // **VERIFICAÇÃO DE SENHA SEGURA**:
                // Use password_verify() para comparar a senha digitada com o hash armazenado.
                if (password_verify($senha_digitada, $senha_hash_armazenada)) {
                    // Login válido, agora verificamos o tipo de usuário
                    if ($tipo_usuario === 'administrador') {
                        header("Location: adm.php"); // Redireciona para a página do administrador
                        exit(); // É crucial usar exit() após um redirecionamento
                    } elseif ($tipo_usuario === 'vendedor') {
                        header("Location: profissional.php"); // Redireciona para a página do vendedor
                        exit();
                    } elseif ($tipo_usuario === 'cliente') {
                        header("Location: compra.php"); // Redireciona para a página do cliente
                        exit();
                    } else {
                        // Caso o tipo de usuário seja desconhecido (erro ou tipo novo)
                        echo "Tipo de usuário desconhecido. Entre em contato com o suporte.";
                    }
                } else {
                    echo "Email ou senha inválidos."; // Senha incorreta
                }
            } else {
                echo "Email ou senha inválidos."; // Email não encontrado
            }
        } else {
            // Trata erros na execução da consulta
            echo "Erro ao realizar a consulta: " . $stmt->error;
        }

        $stmt->close(); // Fecha o statement
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="inicio.css">
  <title>Login</title>
</head>

<body>
<header>
        <h1>Sorveteria Delícia</h1>
        <nav>
            <ul>
                <li><a href="index.php">HOME</a></li>
                
                <li><a href="contato.html">CONTATO</a></li>
                
              </ul>
        </nav>
    </header>
<h2>LOGIN</h2>
  <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required>
        <label for="senha">Senha:</label>
        <input type="password" id="senha" name="senha"  required>

        <button type="submit">Entrar</button>
    </form> 

</body>
</html>

