package br.com.mega.condominio.repository;

import org.springframework.data.repository.CrudRepository;

import br.com.mega.condominio.models.Usuario;

public interface UsuarioRepository extends CrudRepository<Usuario, String>{

	Usuario findByLogin(String login);
}